// Copyright 2012 Google, Inc. All rights reserved.
// Copyright 2009-2011 Andreas Krennmair. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

// bytediff provides a simple diff utility for looking at differences in byte
// slices.  It's slow, clunky, and not particularly good by any measure, but
// it's only used for our tests here at the moment so I'm okay with it.  Please
// don't export any of this functionality, though.
//
// We use this logic in tests to show the differences between byte slices.  Our
// diff algorithm uses a dynamic programming implementation of longest common
// substring to find matching parts of slices, then recursively calls itself on
// the prefix/suffix of that matching part for each packet.  This is a Bad Idea
// (tm) in general, but for packets where large portions repeate infrequently
// and we expect minor changes between results, it's good enough.

import (
	"bytes"
	"fmt"
)

const (
	// bashg color escape codes
	termColorReset  = "\033[0m"
	termColorRed    = "\033[32m"
	termColorGreen  = "\033[31m"
	termColorYellow = "\033[33m"
)

// longestCommonSubstring uses a O(MN) dynamic programming approach to find the
// longest common substring in a set of slices.  It returns the index in each
// slice at which the substring begins, plus the length of the commonality.
func longestCommonSubstring(strA, strB []byte) (indexA, indexB, length int) {
	lenA, lenB := len(strA), len(strB)
	if lenA == 0 || lenB == 0 {
		return 0, 0, 0
	}
	arr := make([][]int, lenA)
	for i := 0; i < lenA; i++ {
		arr[i] = make([]int, lenB)
	}
	var maxLength int
	var maxA, maxB int
	for a := 0; a < lenA; a++ {
		for b := 0; b < lenB; b++ {
			if strA[a] == strB[b] {
				length := 1
				if a > 0 && b > 0 {
					length = arr[a-1][b-1] + 1
				}
				arr[a][b] = length
				if length > maxLength {
					maxLength = length
					maxA = a
					maxB = b
				}
			}
		}
	}
	a, b := maxA, maxB
	for a >= 0 && b >= 0 && strA[a] == strB[b] {
		indexA = a
		indexB = b
		a--
		b--
		length++
	}
	return
}

func intMax(a, b int) int {
	if a > b {
		return a
	}
	return b
}

type difference struct {
	replace          bool
	str, replaceWith []byte
}

// color returns the bash color for a given difference.
func (d *difference) color() string {
	switch {
	case !d.replace:
		return termColorReset
	case len(d.str) == 0:
		return termColorRed
	case len(d.replaceWith) == 0:
		return termColorGreen
	default:
		return termColorYellow
	}
}

// diffInternal diffs strA and strB, returning a list of differences which
// can be used to construct either the original or new string.
func diffInternal(strA, strB []byte) []difference {
	if len(strA) == 0 && len(strB) == 0 {
		return nil
	}
	ia, ib, l := longestCommonSubstring(strA, strB)
	if l == 0 {
		return []difference{
			difference{true, strA, strB},
		}
	}
	beforeA, match, afterA := strA[:ia], strA[ia:ia+l], strA[ia+l:]
	beforeB, afterB := strB[:ib], strB[ib+l:]
	var diffs []difference
	diffs = append(diffs, diffInternal(beforeA, beforeB)...)
	diffs = append(diffs, difference{false, match, nil})
	diffs = append(diffs, diffInternal(afterA, afterB)...)
	return diffs
}

// diffString diffs strA and strB and writes out the result as a
// bash-colorized string that's very easy to read.
func diffString(strA, strB []byte) string {
	var buf bytes.Buffer
	count := 0
	diffs := diffInternal(strA, strB)
	fmt.Fprintf(&buf, "00000000 ")
	for i := 0; i < len(diffs); i++ {
		diff := diffs[i]
		fmt.Fprint(&buf, diff.color())
		for _, b := range diff.str {
			fmt.Fprintf(&buf, " %02x", b)
			count++
			switch count % 16 {
			case 0:
				fmt.Fprintf(&buf, "%v\n%08x%v ", termColorReset, count, diff.color())
			case 8:
				fmt.Fprintf(&buf, " ")
			}
		}
		fmt.Fprint(&buf, termColorReset)
	}
	fmt.Fprintf(&buf, "\n\n00000000 ")
	count = 0
	for i := 0; i < len(diffs); i++ {
		diff := diffs[i]
		str := diff.str
		if diff.replace {
			str = diff.replaceWith
		}
		fmt.Fprint(&buf, diff.color())
		for _, b := range str {
			fmt.Fprintf(&buf, " %02x", b)
			count++
			switch count % 16 {
			case 0:
				fmt.Fprintf(&buf, "%v\n%08x%v ", termColorReset, count, diff.color())
			case 8:
				fmt.Fprintf(&buf, " ")
			}
		}
		fmt.Fprint(&buf, termColorReset)
	}
	fmt.Fprint(&buf, "\n\n")
	return string(buf.Bytes())
}

// Copyright 2018 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"bytes"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"

	"github.com/google/gopacket"
)

// FTPCommand defines the different commands fo the FTP Protocol
type FTPCommand uint16

// Here are all the FTP commands
const (
	FTPCommandAbor FTPCommand = iota + 1 // ABOR Abort an active file transfer.
	FTPCommandAcct                       // ACCT Account information.
	FTPCommandAdat                       // ADAT RFC 2228 Authentication/Security Data
	FTPCommandAllo                       // ALLO Allocate sufficient disk space to receive a file.
	FTPCommandAppe                       // APPE Append (with create)
	FTPCommandAuth                       // AUTH RFC 2228 Authentication/Security Mechanism
	FTPCommandAvbl                       // AVBL Streamlined FTP Command Extensions Get the available space
	FTPCommandCcc                        // CCC RFC 2228 Clear Command Channel
	FTPCommandCdup                       // CDUP Change to Parent Directory.
	FTPCommandConf                       // CONF RFC 2228 Confidentiality Protection Command
	FTPCommandCsid                       // CSID Streamlined FTP Command Extensions Client / Server Identification
	FTPCommandCwd                        // CWD RFC 697 Change working directory.
	FTPCommandDele                       // DELE Delete file.
	FTPCommandDsiz                       // DSIZ Streamlined FTP Command Extensions Get the directory size
	FTPCommandEnc                        // ENC RFC 2228 Privacy Protected Channel
	FTPCommandEprt                       // EPRT RFC 2428 Specifies an extended address and port to which the server should connect.
	FTPCommandEpsv                       // EPSV RFC 2428 Enter extended passive mode.
	FTPCommandFeat                       // FEAT RFC 2389 Get the feature list implemented by the server.
	FTPCommandHelp                       // HELP Returns usage documentation on a command if specified, else a general help document is returned.
	FTPCommandHost                       // HOST RFC 7151 Identify desired virtual host on server, by name.
	FTPCommandLang                       // LANG RFC 2640 Language Negotiation
	FTPCommandList                       // LIST Returns information of a file or directory if specified, else information of the current working directory is returned.
	FTPCommandLprt                       // LPRT RFC 1639 Specifies a long address and port to which the server should connect.
	FTPCommandLpsv                       // LPSV RFC 1639 Enter long passive mode.
	FTPCommandMdtm                       // MDTM RFC 3659 Return the last-modified time of a specified file.
	FTPCommandMfct                       // MFCT The 'MFMT', 'MFCT', and 'MFF' Command Extensions for FTP Modify the creation time of a file.
	FTPCommandMff                        // MFF The 'MFMT', 'MFCT', and 'MFF' Command Extensions for FTP Modify fact (the last modification time, creation time, UNIX group/owner/mode of a file).
	FTPCommandMfmt                       // MFMT The 'MFMT', 'MFCT', and 'MFF' Command Extensions for FTP Modify the last modification time of a file.
	FTPCommandMic                        // MIC RFC 2228 Integrity Protected Command
	FTPCommandMkd                        // MKD Make directory.
	FTPCommandMlsd                       // MLSD RFC 3659 Lists the contents of a directory if a directory is named.
	FTPCommandMlst                       // MLST RFC 3659 Provides data about exactly the object named on its command line, and no others.
	FTPCommandMode                       // MODE Sets the transfer mode (Stream, Block, or Compressed).
	FTPCommandNlst                       // NLST Returns a list of file names in a specified directory.
	FTPCommandNoop                       // NOOP No operation (dummy packet; used mostly on keepalives).
	FTPCommandOpts                       // OPTS RFC 2389 Select options for a feature (for example OPTS UTF8 ON).
	FTPCommandPass                       // PASS Authentication password.
	FTPCommandPasv                       // PASV Enter passive mode.
	FTPCommandPbsz                       // PBSZ RFC 2228 Protection Buffer Size
	FTPCommandPort                       // PORT Specifies an address and port to which the server should connect.
	FTPCommandProt                       // PROT RFC 2228 Data Channel Protection Level.
	FTPCommandPwd                        // PWD Print working directory. Returns the current directory of the host.
	FTPCommandQuit                       // QUIT Disconnect.
	FTPCommandRein                       // REIN Re initializes the connection.
	FTPCommandRest                       // REST RFC 3659 Restart transfer from the specified point.
	FTPCommandRetr                       // RETR Retrieve a copy of the file
	FTPCommandRmd                        // RMD Remove a directory.
	FTPCommandRmda                       // RMDA Streamlined FTP Command Extensions Remove a directory tree
	FTPCommandRnfr                       // RNFR Rename from.
	FTPCommandRnto                       // RNTO Rename to.
	FTPCommandSite                       // SITE Sends site specific commands to remote server (like SITE IDLE 60 or SITE UMASK 002). Inspect SITE HELP output for complete list of supported commands.
	FTPCommandSize                       // SIZE RFC 3659 Return the size of a file.
	FTPCommandSmnt                       // SMNT Mount file structure.
	FTPCommandSpsv                       // SPSV FTP Extension Allowing IP Forwarding (NATs) Use single port passive mode (only one TCP port number for both control connections and passive-mode data connections)
	FTPCommandStat                       // STAT Returns the current status.
	FTPCommandStor                       // STOR Accept the data and to store the data as a file at the server site
	FTPCommandStou                       // STOU Store file uniquely.
	FTPCommandStru                       // STRU Set file transfer structure.
	FTPCommandSyst                       // SYST Return system type.
	FTPCommandThmb                       // THMB Streamlined FTP Command Extensions Get a thumbnail of a remote image file
	FTPCommandType                       // TYPE Sets the transfer mode (ASCII/Binary).
	FTPCommandUser                       // USER Authentication username.
	FTPCommandXcup                       // XCUP RFC 775 Change to the parent of the current working directory
	FTPCommandXmkd                       // XMKD RFC 775 Make a directory
	FTPCommandXpwd                       // XPWD RFC 775 Print the current working directory
	FTPCommandXrcp                       // XRCP RFC 743
	FTPCommandXrmd                       // XRMD RFC 775 Remove the directory
	FTPCommandXrsq                       // XRSQ RFC 743
	FTPCommandXsem                       // XSEM RFC 737 Send, mail if cannot
	FTPCommandXsen                       // XSEN RFC 737 Send to terminal
)

func (fc FTPCommand) String() string {
	switch fc {
	case FTPCommandAbor:
		return "ABOR"
	case FTPCommandAcct:
		return "ACCT"
	case FTPCommandAdat:
		return "ADAT"
	case FTPCommandAllo:
		return "ALLO"
	case FTPCommandAppe:
		return "APPE"
	case FTPCommandAuth:
		return "AUTH"
	case FTPCommandAvbl:
		return "AVBL"
	case FTPCommandCcc:
		return "CCC"
	case FTPCommandCdup:
		return "CDUP"
	case FTPCommandConf:
		return "CONF"
	case FTPCommandCsid:
		return "CSID"
	case FTPCommandCwd:
		return "CWD"
	case FTPCommandDele:
		return "DELE"
	case FTPCommandDsiz:
		return "DSIZ"
	case FTPCommandEnc:
		return "ENC"
	case FTPCommandEprt:
		return "EPRT"
	case FTPCommandEpsv:
		return "EPSV"
	case FTPCommandFeat:
		return "FEAT"
	case FTPCommandHelp:
		return "HELP"
	case FTPCommandHost:
		return "HOST"
	case FTPCommandLang:
		return "LANG"
	case FTPCommandList:
		return "LIST"
	case FTPCommandLprt:
		return "LPRT"
	case FTPCommandLpsv:
		return "LPSV"
	case FTPCommandMdtm:
		return "MDTM"
	case FTPCommandMfct:
		return "MFCT"
	case FTPCommandMff:
		return "MFF"
	case FTPCommandMfmt:
		return "MFMT"
	case FTPCommandMic:
		return "MIC"
	case FTPCommandMkd:
		return "MKD"
	case FTPCommandMlsd:
		return "MLSD"
	case FTPCommandMlst:
		return "MLST"
	case FTPCommandMode:
		return "MODE"
	case FTPCommandNlst:
		return "NLST"
	case FTPCommandNoop:
		return "NOOP"
	case FTPCommandOpts:
		return "OPTS"
	case FTPCommandPass:
		return "PASS"
	case FTPCommandPasv:
		return "PASV"
	case FTPCommandPbsz:
		return "PBSZ"
	case FTPCommandPort:
		return "PORT"
	case FTPCommandProt:
		return "PROT"
	case FTPCommandPwd:
		return "PWD"
	case FTPCommandQuit:
		return "QUIT"
	case FTPCommandRein:
		return "REIN"
	case FTPCommandRest:
		return "REST"
	case FTPCommandRetr:
		return "RETR"
	case FTPCommandRmd:
		return "RMD"
	case FTPCommandRmda:
		return "RMDA"
	case FTPCommandRnfr:
		return "RNFR"
	case FTPCommandRnto:
		return "RNTO"
	case FTPCommandSite:
		return "SITE"
	case FTPCommandSize:
		return "SIZE"
	case FTPCommandSmnt:
		return "SMNT"
	case FTPCommandSpsv:
		return "SPSV"
	case FTPCommandStat:
		return "STAT"
	case FTPCommandStor:
		return "STOR"
	case FTPCommandStou:
		return "STOU"
	case FTPCommandStru:
		return "STRU"
	case FTPCommandSyst:
		return "SYST"
	case FTPCommandThmb:
		return "THMB"
	case FTPCommandType:
		return "TYPE"
	case FTPCommandUser:
		return "USER"
	case FTPCommandXcup:
		return "XCUP"
	case FTPCommandXmkd:
		return "XMKD"
	case FTPCommandXpwd:
		return "XPWD"
	case FTPCommandXrcp:
		return "XRCP"
	case FTPCommandXrmd:
		return "XRMD"
	case FTPCommandXrsq:
		return "XRSQ"
	case FTPCommandXsem:
		return "XSEM"
	case FTPCommandXsen:
		return "XSEN"
	default:
		return "Unknown command"
	}
}

// GetFTPCommand returns the constant of a FTP command from its string
func GetFTPCommand(command string) (FTPCommand, error) {
	switch strings.ToUpper(command) {
	case "ABOR":
		return FTPCommandAbor, nil
	case "ACCT":
		return FTPCommandAcct, nil
	case "ADAT":
		return FTPCommandAdat, nil
	case "ALLO":
		return FTPCommandAllo, nil
	case "APPE":
		return FTPCommandAppe, nil
	case "AUTH":
		return FTPCommandAuth, nil
	case "AVBL":
		return FTPCommandAvbl, nil
	case "CCC":
		return FTPCommandCcc, nil
	case "CDUP":
		return FTPCommandCdup, nil
	case "CONF":
		return FTPCommandConf, nil
	case "CSID":
		return FTPCommandCsid, nil
	case "CWD":
		return FTPCommandCwd, nil
	case "DELE":
		return FTPCommandDele, nil
	case "DSIZ":
		return FTPCommandDsiz, nil
	case "ENC":
		return FTPCommandEnc, nil
	case "EPRT":
		return FTPCommandEprt, nil
	case "EPSV":
		return FTPCommandEpsv, nil
	case "FEAT":
		return FTPCommandFeat, nil
	case "HELP":
		return FTPCommandHelp, nil
	case "HOST":
		return FTPCommandHost, nil
	case "LANG":
		return FTPCommandLang, nil
	case "LIST":
		return FTPCommandList, nil
	case "LPRT":
		return FTPCommandLprt, nil
	case "LPSV":
		return FTPCommandLpsv, nil
	case "MDTM":
		return FTPCommandMdtm, nil
	case "MFCT":
		return FTPCommandMfct, nil
	case "MFF":
		return FTPCommandMff, nil
	case "MFMT":
		return FTPCommandMfmt, nil
	case "MIC":
		return FTPCommandMic, nil
	case "MKD":
		return FTPCommandMkd, nil
	case "MLSD":
		return FTPCommandMlsd, nil
	case "MLST":
		return FTPCommandMlst, nil
	case "MODE":
		return FTPCommandMode, nil
	case "NLST":
		return FTPCommandNlst, nil
	case "NOOP":
		return FTPCommandNoop, nil
	case "OPTS":
		return FTPCommandOpts, nil
	case "PASS":
		return FTPCommandPass, nil
	case "PASV":
		return FTPCommandPasv, nil
	case "PBSZ":
		return FTPCommandPbsz, nil
	case "PORT":
		return FTPCommandPort, nil
	case "PROT":
		return FTPCommandProt, nil
	case "PWD":
		return FTPCommandPwd, nil
	case "QUIT":
		return FTPCommandQuit, nil
	case "REIN":
		return FTPCommandRein, nil
	case "REST":
		return FTPCommandRest, nil
	case "RETR":
		return FTPCommandRetr, nil
	case "RMD":
		return FTPCommandRmd, nil
	case "RMDA":
		return FTPCommandRmda, nil
	case "RNFR":
		return FTPCommandRnfr, nil
	case "RNTO":
		return FTPCommandRnto, nil
	case "SITE":
		return FTPCommandSite, nil
	case "SIZE":
		return FTPCommandSize, nil
	case "SMNT":
		return FTPCommandSmnt, nil
	case "SPSV":
		return FTPCommandSpsv, nil
	case "STAT":
		return FTPCommandStat, nil
	case "STOR":
		return FTPCommandStor, nil
	case "STOU":
		return FTPCommandStou, nil
	case "STRU":
		return FTPCommandStru, nil
	case "SYST":
		return FTPCommandSyst, nil
	case "THMB":
		return FTPCommandThmb, nil
	case "TYPE":
		return FTPCommandType, nil
	case "USER":
		return FTPCommandUser, nil
	case "XCUP":
		return FTPCommandXcup, nil
	case "XMKD":
		return FTPCommandXmkd, nil
	case "XPWD":
		return FTPCommandXpwd, nil
	case "XRCP":
		return FTPCommandXrcp, nil
	case "XRMD":
		return FTPCommandXrmd, nil
	case "XRSQ":
		return FTPCommandXrsq, nil
	case "XSEM":
		return FTPCommandXsem, nil
	case "XSEN":
		return FTPCommandXsen, nil
	default:
		return 0, fmt.Errorf("Unknown FTP command: '%s'", command)
	}
}

// FTP object contains information about an FTP packet
type FTP struct {
	BaseLayer

	Command    FTPCommand
	CommandArg string

	IsResponse     bool
	ResponseCode   int
	ResponseStatus string

	Delimiter string
}

func decodeFTP(data []byte, p gopacket.PacketBuilder) error {
	f := &FTP{}
	err := f.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}
	p.AddLayer(f)
	p.SetApplicationLayer(f)
	return nil

}

// LayerType returns gopacket.LayerTypeFTP
func (f *FTP) LayerType() gopacket.LayerType { return LayerTypeFTP }

// Payload returns the base layer payload (nil)
func (f *FTP) Payload() []byte { return nil }

// CanDecode returns gopacket.LayerTypeFTP
func (f *FTP) CanDecode() gopacket.LayerClass { return LayerTypeFTP }

// NextLayerType returns gopacket.LayerTypeZero
func (f *FTP) NextLayerType() gopacket.LayerType { return gopacket.LayerTypeZero }

// DecodeFromBytes decodes the slice into the FTP struct.
func (f *FTP) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	var countLines int
	var line []byte
	var err error

	f.BaseLayer = BaseLayer{Contents: data[:len(data)]}

	// Clean leading new line
	data = bytes.Trim(data, "\n")

	buffer := bytes.NewBuffer(data)

	var lastLine bool
	for {
		// Read next line
		line, err = buffer.ReadBytes(byte('\n'))
		if err != nil {
			if err == io.EOF {
				lastLine = true
			} else {
				return err
			}
		}

		// Trim the new line delimiters
		line = bytes.Trim(line, "\r\n")

		if countLines == 0 {
			err = f.parseFirstLine(line)
			if err != nil {
				return err
			}
		} else {
			err = f.parseFollowupLine(line)
			if err != nil {
				return err
			}
		}
		countLines++
		if lastLine {
			break
		}
	}

	return nil
}

func (f *FTP) parseFirstLine(line []byte) error {
	var err error
	if len(line) < 3 {
		return fmt.Errorf("invalid first FTP line: '%s'", string(line))
	}

	re := regexp.MustCompile("^([0-9]{3})(.?)(.*)")
	if res := re.FindStringSubmatch(string(line)); res != nil {
		f.IsResponse = true
		f.ResponseCode, err = strconv.Atoi(res[1])
		if err != nil {
			return err
		}
		f.Delimiter = res[2]
		f.ResponseStatus = res[3]
	} else {
		splits := strings.SplitN(string(line), " ", 2)
		f.Command, err = GetFTPCommand(splits[0])
		if err != nil {
			return err
		}
		if len(splits) > 1 {
			f.Delimiter = " "
			f.CommandArg = splits[1]
		}
	}
	return nil
}

func (f *FTP) parseFollowupLine(line []byte) error {
	if f.IsResponse {
		f.ResponseStatus += "\n" + string(line)
	} else {
		f.CommandArg += "\n" + string(line)
	}
	return nil
}

// SerializeTo writes the serialized form of this layer into the
// SerializationBuffer, implementing gopacket.SerializableLayer.
func (f *FTP) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	if f.IsResponse {
		bytes, err := b.PrependBytes(len(f.ResponseStatus) + len(f.Delimiter) + 5)
		if err != nil {
			return err
		}
		copy(bytes[0:3], fmt.Sprintf("%03d", f.ResponseCode))
		copy(bytes[3:], f.Delimiter+f.ResponseStatus+"\r\n")
	} else {
		bytes, err := b.PrependBytes(len(f.Command.String()) + len(f.Delimiter) + len(f.CommandArg) + 2)
		if err != nil {
			return err
		}
		copy(bytes[0:], f.Command.String()+f.Delimiter+f.CommandArg+"\r\n")
	}
	return nil
}

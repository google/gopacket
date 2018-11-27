SET GOARCH=386
go tool cgo -godefs -- -I C:\npcap-sdk-1.01\Include gen_defs_windows.go | gofmt > defs_windows_386.go
SET GOARCH=amd64
go tool cgo -godefs -- -I C:\npcap-sdk-1.01\Include gen_defs_windows.go | gofmt > defs_windows_amd64.go
SET GOARCH=
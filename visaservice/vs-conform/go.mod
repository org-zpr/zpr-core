module zpr.org/vst

go 1.23.3

require (
	github.com/apache/thrift v0.21.0
	github.com/fatih/color v1.18.0
	github.com/google/gopacket v1.1.19
	go.uber.org/zap v1.27.0
	google.golang.org/protobuf v1.35.2
	zpr.org/vsapi v0.2.0
	zpr.org/vsx/polio v0.0.0-00010101000000-000000000000
)

require (
	github.com/cpuguy83/go-md2man/v2 v2.0.5 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/russross/blackfriday/v2 v2.1.0 // indirect
	github.com/urfave/cli/v2 v2.27.5 // indirect
	github.com/xrash/smetrics v0.0.0-20240521201337-686a1a2994c1 // indirect
	go.uber.org/multierr v1.10.0 // indirect
	golang.org/x/sys v0.25.0 // indirect
)

replace zpr.org/vsapi => github.com/org-zpr/zpr-vsapi-go v0.2.0

replace zpr.org/vsx/polio => ../mods/polio

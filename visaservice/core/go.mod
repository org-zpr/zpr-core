module zpr.org/vs

go 1.22.2

require (
	github.com/apache/thrift v0.20.0
	github.com/golang-jwt/jwt/v5 v5.2.1
	github.com/google/gopacket v1.1.19
	github.com/google/uuid v1.6.0
	github.com/gorilla/mux v1.8.1
	github.com/hashicorp/go-version v1.7.0
	github.com/stretchr/testify v1.9.0
	github.com/urfave/cli/v2 v2.27.2
	go.uber.org/zap v1.27.0
	golang.org/x/net v0.26.0
	google.golang.org/grpc v1.64.0
	google.golang.org/protobuf v1.34.2
	gopkg.in/yaml.v2 v2.4.0
	zpr.org/vsapi v0.1.0
	zpr.org/vsx/polio v0.0.0-00010101000000-000000000000
	zpr.org/vsx/snio v0.0.0-00010101000000-000000000000
	zpr.org/vsx/zpl v0.0.0-00010101000000-000000000000
)

require (
	github.com/cpuguy83/go-md2man/v2 v2.0.4 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/klauspost/cpuid/v2 v2.0.12 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/russross/blackfriday/v2 v2.1.0 // indirect
	github.com/xrash/smetrics v0.0.0-20240312152122-5f08fbb34913 // indirect
	go.uber.org/multierr v1.10.0 // indirect
	golang.org/x/exp v0.0.0-20240604190554-fc45aab8b7f8 // indirect
	golang.org/x/sys v0.21.0 // indirect
	golang.org/x/text v0.16.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20240318140521-94a12d6c2237 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace zpr.org/vsapi => github.com/org-zpr/zpr-vsapi-go v0.1.0

replace zpr.org/vsx/polio => ../mods/polio

replace zpr.org/vsx/snio => ../mods/snio

replace zpr.org/vsx/zpl => ../mods/zpl

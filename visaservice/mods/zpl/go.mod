module zpr.org/vsx/zpl

go 1.22.2

require (
	github.com/stretchr/testify v1.9.0
	golang.org/x/exp v0.0.0-20240604190554-fc45aab8b7f8
	google.golang.org/grpc v1.64.0
	gopkg.in/yaml.v3 v3.0.1
	zpr.org/vsx/polio v0.0.0-00010101000000-000000000000
	zpr.org/vsx/snio v0.0.0-00010101000000-000000000000
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	golang.org/x/net v0.22.0 // indirect
	golang.org/x/sys v0.18.0 // indirect
	golang.org/x/text v0.14.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20240318140521-94a12d6c2237 // indirect
	google.golang.org/protobuf v1.34.2 // indirect
)

replace zpr.org/vsx/snio => ../snio

replace zpr.org/vsx/polio => ../polio

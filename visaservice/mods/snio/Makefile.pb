PROTOS := $(wildcard *.proto)

PBGENS := $(PROTOS:.proto=.pb.go)

all: $(PBGENS)
	cd admin && $(MAKE) all
	cd zds && $(MAKE) all
	cd zds2 && $(MAKE) all
	cd vsio && $(MAKE) all

clean:
	rm -f *.pb.go
	cd admin && $(MAKE) clean
	cd zds && $(MAKE) clean
	cd zds2 && $(MAKE) clean
	cd vsio && $(MAKE) clean

%.pb.go: %.proto
	protoc -I. --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative $<



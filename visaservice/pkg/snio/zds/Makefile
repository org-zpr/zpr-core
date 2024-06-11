PROTOS := $(wildcard *.proto)

PBGENS := $(PROTOS:.proto=.pb.go)

all: $(PBGENS)

clean:
	rm -f *.pb.go

%.pb.go: %.proto
	protoc --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative $<



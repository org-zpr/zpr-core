PROTOS := $(wildcard *.proto)

PBGENS := $(PROTOS:.proto=.pb.go)

all: $(PBGENS)

clean:
	rm -f *.pb.go

%.pb.go: %.proto
	protoc -I../ --go_out=paths=source_relative:../ --go_opt=paths=source_relative --go-grpc_out=paths=source_relative:../ --go-grpc_opt=paths=source_relative vss/$<



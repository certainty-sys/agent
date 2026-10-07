all: lint build

# test: $(SOURCE)
# 	cd src && go test -v

lint:
	go vet ./...

build: lint
	CGO_ENABLED=0 go build -v -ldflags="-w -s" -o agent

# coverage:
# 	cd src && go test -coverprofile=../coverage.out -v && go tool cover -html=../coverage.out

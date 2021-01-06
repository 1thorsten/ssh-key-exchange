create_git_tag:
	git describe --abbrev=0 --tags > version_git_tag

build: create_git_tag
	mkdir -p bin
	go build -ldflags="-s -w" -o bin/ssh-key-exchange .

build_darwin_amd64:
	mkdir -p bin/darwin_amd64
	GOOS=darwin GOARCH=amd64 go build -ldflags="-s -w" -o bin/darwin_amd64/ssh-key-exchange .

build_linux_amd64:
	mkdir -p bin/linux_amd64
	GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o bin/linux_amd64/ssh-key-exchange .

build_windows_amd64:
	mkdir -p bin/windows_amd64
	GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o bin/windows_amd64/ssh-key-exchange.exe .

build-all: create_git_tag build_darwin_amd64 build_linux_amd64 build_windows_amd64

install: build
	go install

format:
	gofmt -w -d -s *.go

.PHONY: build install format

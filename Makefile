update_dependencies:
	go get -u all

create_git_tag:
	git pull
	git tag 1.0.5

retrieve_git_tag:
	git pull
	git describe --abbrev=0 --tags > src/version_git_tag

build: retrieve_git_tag
	mkdir -p bin
	go build -ldflags="-s -w" -o bin/ssh-key-exchange ./src

build_darwin_amd64:
	mkdir -p bin/darwin_amd64
	GOOS=darwin GOARCH=amd64 go build -ldflags="-s -w" -o bin/darwin_amd64/ssh-key-exchange ./src

build_linux_amd64:
	mkdir -p bin/linux_amd64
	GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o bin/linux_amd64/ssh-key-exchange ./src

build_windows_amd64:
	mkdir -p bin/windows_amd64
	GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o bin/windows_amd64/ssh-key-exchange.exe ./src

build-all: retrieve_git_tag build_darwin_amd64 build_linux_amd64 build_windows_amd64

install: build
	go install

format:
	gofmt -w -d -s *.go

.PHONY: build install format

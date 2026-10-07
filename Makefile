.PHONY: build-client test-client build-agent bpf compose

build-client:
	npm run build

test-client:
	npm test

bpf:
	cd bpf && ./compile.sh

build-agent:
	cd agent && go build -o ../bin/node-vault-ebpf-agent ./cmd/node-vault-ebpf-agent

compose:
	docker compose -f docker/docker-compose.yml up --build

test-agent:
	docker run --rm -v "$(CURDIR):/src" -w /src/agent golang:1.22 go test ./...

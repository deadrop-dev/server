BINARY := deadrop-server

.PHONY: build test vet fmt clean docker

build:
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o $(BINARY) ./cmd/deadrop-server

test:
	go test ./...

vet:
	go vet ./...
	@out="$$(gofmt -l .)"; if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi

clean:
	rm -f $(BINARY) $(BINARY).exe

docker:
	docker build -t deadrop-server .

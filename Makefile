VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)
GOFLAGS := CGO_ENABLED=0 GOOS=linux GOARCH=amd64

# Override these to point at your hosts, e.g.
#   make deploy-frontend FRONTEND_HOST=root@dc.example.net
FRONTEND_HOST ?= root@frontend
BACKEND_HOST  ?= root@backend

# Every Go source, plus the assets embedded into the portal. Without these
# prerequisites the build/ targets are satisfied by the file already being
# there, so `make build` after a code change is a no-op and deploy-* ships
# the previous binary - which looks exactly like the change not working.
SOURCES := $(wildcard cmd/*/*.go internal/*/*.go internal/web/static/*) go.mod go.sum

.PHONY: all build linker test vet fmt clean deploy-frontend deploy-backend deploy-linker

all: test build

build: build/failover-frontend build/failover-backend build/failoverctl

# Deliberately not in `build`. A linker is an optional extra host that most
# sites never run, and building it by default invites installing it by default.
linker: build/failover-linker

build/failover-frontend: $(SOURCES)
	@mkdir -p build
	$(GOFLAGS) go build -ldflags="$(LDFLAGS)" -o $@ ./cmd/failover-frontend

build/failover-backend: $(SOURCES)
	@mkdir -p build
	$(GOFLAGS) go build -ldflags="$(LDFLAGS)" -o $@ ./cmd/failover-backend

build/failover-linker: $(SOURCES)
	@mkdir -p build
	$(GOFLAGS) go build -ldflags="$(LDFLAGS)" -o $@ ./cmd/failover-linker

build/failoverctl: $(SOURCES)
	@mkdir -p build
	$(GOFLAGS) go build -ldflags="$(LDFLAGS)" -o $@ ./cmd/failoverctl

test:
	go test ./...

vet:
	go vet ./...

fmt:
	gofmt -w ./cmd ./internal

clean:
	rm -rf build

# Deploying replaces the binary and restarts the unit. The agent never created
# the WireGuard tunnels, so a restart cannot take the links down; the worst
# case is that path selection pauses for a second.
deploy-frontend: build/failover-frontend build/failoverctl
	ssh $(FRONTEND_HOST) 'mkdir -p /etc/failover /var/lib/failover'
	scp build/failover-frontend $(FRONTEND_HOST):/usr/local/bin/failover-frontend.new
	scp build/failoverctl $(FRONTEND_HOST):/usr/local/bin/failoverctl.new
	scp deploy/failover-frontend.service $(FRONTEND_HOST):/etc/systemd/system/failover-frontend.service
	ssh $(FRONTEND_HOST) 'mv /usr/local/bin/failover-frontend.new /usr/local/bin/failover-frontend && \
		mv /usr/local/bin/failoverctl.new /usr/local/bin/failoverctl && \
		chmod 0755 /usr/local/bin/failover-frontend /usr/local/bin/failoverctl && \
		systemctl daemon-reload && systemctl enable --now failover-frontend && \
		systemctl restart failover-frontend && sleep 1 && systemctl --no-pager status failover-frontend'

deploy-backend: build/failover-backend
	ssh $(BACKEND_HOST) 'mkdir -p /etc/failover /var/lib/failover'
	scp build/failover-backend $(BACKEND_HOST):/usr/local/bin/failover-backend.new
	scp deploy/failover-backend.service $(BACKEND_HOST):/etc/systemd/system/failover-backend.service
	ssh $(BACKEND_HOST) 'mv /usr/local/bin/failover-backend.new /usr/local/bin/failover-backend && \
		chmod 0755 /usr/local/bin/failover-backend && \
		systemctl daemon-reload && systemctl enable --now failover-backend && \
		systemctl restart failover-backend && sleep 1 && systemctl --no-pager status failover-backend'

# LINKER_HOST is one machine at a time: each linker has its own overlay address
# in its own bootstrap file, so there is nothing to loop over safely.
LINKER_HOST ?= root@linker

deploy-linker: build/failover-linker
	ssh $(LINKER_HOST) 'mkdir -p /etc/failover /var/lib/failover'
	scp build/failover-linker $(LINKER_HOST):/usr/local/bin/failover-linker.new
	scp deploy/failover-linker.service $(LINKER_HOST):/etc/systemd/system/failover-linker.service
	ssh $(LINKER_HOST) 'mv /usr/local/bin/failover-linker.new /usr/local/bin/failover-linker && \
		chmod 0755 /usr/local/bin/failover-linker && \
		systemctl daemon-reload && systemctl enable --now failover-linker && \
		systemctl restart failover-linker && sleep 1 && systemctl --no-pager status failover-linker'

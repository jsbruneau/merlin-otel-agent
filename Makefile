.PHONY: all build test scan security-scan export deploy clean

ROUTER_IP ?= 192.168.1.1
ROUTER_PORT ?= 22
ROUTER_USER ?= admin

all: export

build:
	docker buildx build --platform linux/arm64 -t merlin-otel-agent:latest .

test:
	docker buildx build --platform linux/arm64 --target test --progress=plain .

scan: security-scan

security-scan:
	docker buildx build --platform linux/arm64 --target security-scan --progress=plain .

export:
	@mkdir -p dist
	docker buildx build --platform linux/arm64 --target export --output type=local,dest=./dist .
	@echo "Built static binary in ./dist/merlin-otel-agent"

deploy:
	ssh -p $(ROUTER_PORT) $(ROUTER_USER)@$(ROUTER_IP) "mkdir -p /jffs/bin /jffs/etc /jffs/scripts"
	scp -O -P $(ROUTER_PORT) dist/merlin-otel-agent $(ROUTER_USER)@$(ROUTER_IP):/jffs/bin/merlin-otel-agent
	scp -O -P $(ROUTER_PORT) dist/motel.conf.example $(ROUTER_USER)@$(ROUTER_IP):/jffs/etc/motel.conf.example
	scp -O -P $(ROUTER_PORT) dist/services-start $(ROUTER_USER)@$(ROUTER_IP):/jffs/scripts/services-start
	ssh -p $(ROUTER_PORT) $(ROUTER_USER)@$(ROUTER_IP) "[ -f /jffs/etc/motel.conf ] || cp /jffs/etc/motel.conf.example /jffs/etc/motel.conf; chmod +x /jffs/bin/merlin-otel-agent /jffs/scripts/services-start"

clean:
	rm -rf dist build

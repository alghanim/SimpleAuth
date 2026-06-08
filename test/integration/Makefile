# SimpleAuth integration-test harness — self-contained, does NOT touch the
# production docker-compose.yml at the repo root.
COMPOSE := docker compose -f docker-compose.yml
CADIR   := $(CURDIR)/certs

.PHONY: certs up down test logs ps clean

## certs: generate the internal CA + central TLS cert (idempotent)
certs:
	@./certs/gen.sh

## up: stand up the topology (browse https://localhost:9443/admin)
up: certs
	$(COMPOSE) up -d --build

## down: stop everything and wipe volumes
down:
	$(COMPOSE) down -v --remove-orphans

## ps / logs: inspect the running stack
ps:
	$(COMPOSE) ps
logs:
	$(COMPOSE) logs -f

## test: up + run the Go scenario driver (from the repo root) + tear down
test: up
	@cd ../.. && ITEST_CA_FILE=$(CADIR)/ca.crt go test -tags integration -count=1 -v ./test/integration/ ; \
	  rc=$$? ; $(COMPOSE) down -v --remove-orphans ; exit $$rc

## clean: down + remove generated certs
clean: down
	@rm -f certs/ca.crt certs/ca.key certs/central.crt certs/central.key

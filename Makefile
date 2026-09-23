.PHONY: all setup run-audit verify-receipts clean

all: setup run-audit verify-receipts

setup:
	docker compose build

run-audit:
	docker compose run --rm smaos-evaluator

verify-receipts:
	./bin/verify.sh audit_out/trust_passport.json

clean:
	rm -rf audit_out/*
	docker compose down -v

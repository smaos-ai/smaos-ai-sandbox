.PHONY: all setup test test-kernel verify verify-checksums run-audit soak compile-hcl dora-xbrl clean

all: verify-checksums test test-kernel verify

setup:
	pip install -r requirements.txt -r requirements-dev.txt

test:
	python3 -m pytest tests/ -v

test-kernel:
	python3 -m pytest tests/kernel/ -v

verify-checksums:
	python3 scripts/verify_checksums.py

verify:
	./verify.sh
	./bin/verify.sh

compile-hcl:
	python3 -m src.hcl_compiler.cli smaos.hcl --out-dir build/governance

dora-xbrl:
	python3 src/dora_xbrl_compiler.py

run-audit:
	python3 run.py --scenario 504_timeout --export-dir ./audit_out

soak:
	python3 production_soak_test.py

clean:
	rm -rf audit_out/* audit_out_verify/* build/* .pytest_cache __pycache__ *.pyc

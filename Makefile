.PHONY: all setup test verify run-audit soak clean

all: test verify

setup:
	pip install -r requirements.txt -r requirements-dev.txt

test:
	python3 -m pytest tests/ -v

verify:
	./verify.sh
	./bin/verify.sh

run-audit:
	python3 run.py --scenario 504_timeout --export-dir ./audit_out

soak:
	python3 production_soak_test.py

clean:
	rm -rf audit_out/* audit_out_verify/* .pytest_cache __pycache__ *.pyc

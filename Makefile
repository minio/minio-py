.PHONY: default
default: tests

getdeps:
	@echo "Installing required dependencies"
	@pip install --user --upgrade certifi pytest pylint urllib3 black

check: getdeps
	@echo "Running checks"
	@pylint --reports=no --score=no --disable=R0401,R0801 minio/*py
	@pylint --reports=no --score=no minio/credentials tests/functional
	@isort --diff .
	@black --check .

apply: getdeps
	@isort .
	@black .

tests: check
	@echo "Running unit tests"
	@pytest
	@echo "Running functional tests"
	@env bash run_functional_tests.sh

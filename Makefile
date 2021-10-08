.PHONY: default
default: tests

getdeps:
	@echo "Installing required dependencies"
	@pip install --user --upgrade autopep8 certifi mock pytest pylint urllib3

check: getdeps
	@echo "Running checks"
	@pylint --reports=no --score=no --disable=R0401,R0801 minio/*py
	@pylint --reports=no --score=no minio/credentials tests/functional
	@isort --diff .
	@find . -name "*.py" -exec autopep8 --diff --exit-code {} +

apply: getdeps
	@isort .
	@find . -name "*.py" -exec autopep8 --in-place {} +

tests: check
	@echo "Running unit tests"
	@pytest
	@echo "Running functional tests"
	@env bash run_functional_tests.sh

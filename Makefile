.PHONY: examples tests publish

getdeps:
	@pip install --user --upgrade pylint autopep8

check: getdeps
	@pylint --reports=no --score=no --disable=R0401,R0801 minio/*py
	@pylint --reports=no --score=no minio/credentials tests/functional
	@isort --diff .
	@find . -name "*.py" -exec autopep8 --diff --exit-code {} +

apply: getdeps
	@isort .
	@find . -name "*.py" -exec autopep8 --in-place {} +

publish:
	python setup.py register
	python setup.py sdist bdist bdist_wheel upload

tests:
	python setup.py nosetests

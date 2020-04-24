.PHONY: examples tests publish

check:
	@which pylint >/dev/null || pip install --user --upgrade pylint
	@if python --version | grep -qi 'python 3'; then pylint --reports=no --score=no --disable=R0401 minio/*py; fi
	@if python --version | grep -qi 'python 3'; then pylint --reports=no --score=no minio/credentials minio/select tests/functional; fi

	@which isort >/dev/null || pip install --user --upgrade isort
	@isort --diff --recursive .

	@which autopep8 >/dev/null || pip install --user --upgrade autopep8
	@autopep8 --diff --exit-code *.py
	@find minio -name "*.py" -exec autopep8 --diff --exit-code {} +
	@find tests -name "*.py" -exec autopep8 --diff --exit-code {} +
	@find examples -name "*.py" -exec autopep8 --diff --exit-code {} +

apply:
	@which isort >/dev/null || pip install --user --upgrade isort
	isort --recursive .

	@which autopep8 >/dev/null || pip install --user --upgrade autopep8
	@autopep8 --in-place *.py
	@find minio -name "*.py" -exec autopep8 --in-place {} +
	@find tests -name "*.py" -exec autopep8 --in-place {} +
	@find examples -name "*.py" -exec autopep8 --in-place {} +

publish:
	python setup.py register
	python setup.py sdist bdist bdist_wheel upload

tests:
	python setup.py nosetests

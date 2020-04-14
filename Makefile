.PHONY: examples tests publish

check:
	@which autopep8 >/dev/null || pip install --user --upgrade autopep8
	@autopep8 --diff --exit-code *.py
	@find minio -name "*.py" -exec autopep8 --diff --exit-code {} +
	@find tests -name "*.py" -exec autopep8 --diff --exit-code {} +
	@find examples -name "*.py" -exec autopep8 --diff --exit-code {} +

publish:
	python setup.py register
	python setup.py sdist bdist bdist_wheel upload

tests:
	python setup.py nosetests

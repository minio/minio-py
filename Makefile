.PHONY: examples

publish:
	python setup.py register
	python setup.py sdist bdist bdist_wheel upload

tests:
	python setup.py nosetests

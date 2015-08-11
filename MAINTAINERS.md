# For maintainers only

### Setup your minio-py Github Repository

Fork [minio-py upstream](https://github.com/minio/minio-py/fork) source repository to your own personal repository.
```bash
$ git clone https://github.com/$USER_ID/minio-py
$ cd minio-py
```

### Publishing new packages

#### Setup your pypirc

Create a new `pypirc`

```bash
$ cat >> $HOME/.pypirc << EOF
[distutils]
index-servers =
    pypi

[pypi]
username:minio
password:**REDACTED**
EOF

```

#### Modify version

```bash
$ cat minio/__version__.py
...
...
# version_info should conform to PEP 386
# (major, minor, micro, alpha/beta/rc/final, #)
# (1, 1, 2, 'alpha', 0) => "1.1.2.dev"
# (1, 2, 0, 'beta', 2) => "1.2b2"
version_info = (0, 3, 0, 'final', 0)
...
...

```

#### Upload to pypi

```bash
$ python setup.py sdist bdist bdist_wheel upload
```
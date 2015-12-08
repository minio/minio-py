# For maintainers only

## Responsibilities

Please go through this link [Maintainer Responsibility](https://gist.github.com/abperiasamy/f4d9b31d3186bbd26522)

## Current Maintainers

- Harshavardhana
- Balamurugan Arumugam

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
$ cat minio/__init__.py
...
...
__version__ = '0.3.0'
...
...

```

#### Upload to pypi

```bash
$ python setup.py sdist bdist bdist_wheel upload
```
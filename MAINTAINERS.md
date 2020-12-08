# For maintainers only

## Responsibilities
Please go through this link [Maintainer Responsibility](https://gist.github.com/abperiasamy/f4d9b31d3186bbd26522)

### Setup your minio-py Github Repository
Fork [minio-py upstream](https://github.com/minio/minio-py/fork) source repository to your own personal repository.
```sh
$ git clone git@github.com:minio/minio-py
$ cd minio-py
$ pip install --user --upgrade twine
```

### Modify package version
```sh
$ cat minio/__init__.py
...
...
__version__ = '2.2.5'
...
...

```

### Build and verify
```sh
$ make
$ python setup.py register
$ python setup.py sdist bdist bdist_wheel
```

### Publishing new packages

#### Setup your pypirc
Create a new `pypirc`

```sh
$ cat >> $HOME/.pypirc << EOF
[distutils]
index-servers =
    pypi

[pypi]
username:minio
password:**REDACTED**
EOF

```

#### Sign
Sign the release artifacts, this step requires you to have access to MinIO's trusted private key.
```sh
$ export GNUPGHOME=/media/${USER}/minio/trusted
$ gpg --detach-sign -a dist/minio-2.2.5.tar.gz
$ gpg --detach-sign -a dist/minio-2.2.5.linux-x86_64.tar.gz
$ gpg --detach-sign -a dist/minio-2.2.5-py2.py3-none-any.whl
```

#### Upload to pypi
Upload the signed release artifacts, please install twine v1.8.0+ for following steps to work properly.
```sh
$ twine upload dist/*
```

### Tag
Tag and sign your release commit, additionally this step requires you to have access to MinIO's trusted private key.
```
$ export GNUPGHOME=/media/${USER}/minio/trusted
$ git tag -s 2.2.5
$ git push
$ git push --tags
```

### Announce
Announce new release by adding release notes at https://github.com/minio/minio-py/releases from `trusted@min.io` account. Release notes requires two sections `highlights` and `changelog`. Highlights is a bulleted list of salient features in this release and Changelog contains list of all commits since the last release.

To generate `changelog`
```sh
git log --no-color --pretty=format:'-%d %s (%cr) <%an>' <last_release_tag>..<latest_release_tag>
```

### Setup your minio-py Github Repository
Fork [minio-py upstream](https://github.com/minio/minio-py/fork) source repository to your own personal repository.

```sh
$ git clone https://github.com/$USER_ID/minio-py
$ cd minio-py
$ python setup.py install
...
```

###  Developer Guidelines

``minio-py`` welcomes your contribution. To make the process as seamless as possible, we ask for the following:

* Go ahead and fork the project and make your changes. We encourage pull requests to discuss code changes.
    - Fork it
    - Create your feature branch (git checkout -b my-new-feature)
    - Commit your changes (git commit -am 'Add some feature')
    - Run [Black](https://github.com/psf/black) and correct related warnings
    - Run [isort](https://github.com/timothycrosley/isort) and correct related warnings
    - Run [pylint](https://github.com/PyCQA/pylint) and correct related warnings
    - Push to the branch (git push origin my-new-feature)
    - Create new Pull Request

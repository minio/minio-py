Minio Python Library for Amazon S3 Compatible Cloud Storage |Gitter|
========

The Minio Python Client SDK provides simple APIs to access any Amazon S3
compatible object storage server.

This quickstart guide will show you how to install the client SDK and
execute an example python program. For a complete list of APIs and
examples, please take a look at the `Python Client API
Reference <https://docs.minio.io/docs/python-client-api-reference>`__
documentation.

This document assumes that you have a working
`Python <https://www.python.org/downloads/>`__ setup in place.

Download from pip
-----------------

.. code:: sh

    $ pip install minio

Download from source
--------------------

.. code:: sh

    $ git clone https://github.com/minio/minio-py
    $ cd minio-py
    $ python setup.py install

Initialize Minio Client
-----------------------

You need four items in order to connect to Minio object storage server.

.. csv-table::
   :header: "Params", "Description"
   :widths: 15, 30

   "endpoint", "URL to object storage service."
   "access_key", "Access key is like user ID that uniquely identifies your account."
   "secret_key", "Secret key is the password to your account."
   "secure", "Set this value to 'True' to enable secure (HTTPS) access."


.. code:: python

    from minio import Minio
    from minio.error import ResponseError

    minioClient = Minio('play.minio.io:9000',
                      access_key='Q3AM3UQ867SPQQA43P2F',
                      secret_key='zuf+tfteSlswRu7BJ86wekitnifILbZam1KYY3TG',
                      secure=True)

Quick Start Example - File Uploader
-----------------------------------

This example program connects to a Minio object storage server, makes a
bucket on the server and then uploads a file to the bucket.

We will use the Minio server running at https://play.minio.io:9000 in
this example. Feel free to use this service for testing and development.
Access credentials shown in this example are open to the public.

file-uploader.py
~~~~~~~~~~~~~~~~

.. code:: python

    # Import Minio library.
    from minio import Minio
    from minio.error import ResponseError

    # Initialize minioClient with an endpoint and access/secret keys.
    minioClient = Minio('play.minio.io:9000',
                        access_key='Q3AM3UQ867SPQQA43P2F',
                        secret_key='zuf+tfteSlswRu7BJ86wekitnifILbZam1KYY3TG',
                        secure=True)

    # Make a bucket with the make_bucket API call.
    try:
           minioClient.make_bucket("maylogs", location="us-east-1")
    except BucketAlreadyOwnedByYou as err:
           pass
    except BucketAlreadyExists as err:
           pass
    except ResponseError as err:
           raise
    else:
           # Put an object 'pumaserver_debug.log' with contents from 'pumaserver_debug.log'.
           try:
                  minioClient.fput_object('maylogs', 'pumaserver_debug.log', '/tmp/pumaserver_debug.log')
           except ResponseError as err:
                  print(err)


Run file-uploader
~~~~~~~~~~~~~~~~~

.. code:: bash

    $ python file_uploader.py

    $ mc ls play/maylogs/
    [2016-05-27 16:41:37 PDT]  12MiB pumaserver_debug.log

API Reference
-------------

The full API Reference is available here. `Complete API
Reference <https://docs.minio.io/docs/python-client-api-reference>`__

API Reference : Bucket Operations
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

-  `make\_bucket <https://docs.minio.io/docs/python-client-api-reference#make_bucket>`__
-  `list\_buckets <https://docs.minio.io/docs/python-client-api-reference#list_buckets>`__
-  `bucket\_exists <https://docs.minio.io/docs/python-client-api-reference#bucket_exists>`__
-  `remove\_bucket <https://docs.minio.io/docs/python-client-api-reference#remove_bucket>`__
-  `list\_objects <https://docs.minio.io/docs/python-client-api-reference#list_objects>`__
-  `list\_incomplete\_uploads <https://docs.minio.io/docs/python-client-api-reference#list_incomplete_uploads>`__
-  `get\_bucket\_policy <https://docs.minio.io/docs/python-client-api-reference#get_bucket_policy>`__
-  `set\_bucket\_policy <https://docs.minio.io/docs/python-client-api-reference#set_bucket_policy>`__

API Reference : File Object Operations
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

-  `fput\_object <https://docs.minio.io/docs/python-client-api-reference#fput_object>`__
-  `fget\_object <https://docs.minio.io/docs/python-client-api-reference#fget_object>`__

API Reference : Object Operations
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

-  `get\_object <https://docs.minio.io/docs/python-client-api-reference#get_object>`__
-  `get\_partial\_object <https://docs.minio.io/docs/python-client-api-reference#get_partial_object>`__
-  `put\_object <https://docs.minio.io/docs/python-client-api-reference#put_object>`__
-  `stat\_object <https://docs.minio.io/docs/python-client-api-reference#stat_object>`__
-  `remove\_object <https://docs.minio.io/docs/python-client-api-reference#remove_object>`__
-  `remove\_incomplete\_upload <https://docs.minio.io/docs/python-client-api-reference#remove_incomplete_upload>`__

API Reference : Presigned Operations
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

-  `presigned\_get\_object <https://docs.minio.io/docs/python-client-api-reference#presigned_get_object>`__
-  `presigned\_put_object <https://docs.minio.io/docs/python-client-api-reference#presigned_put_object>`__
-  `presigned\_post\_policy <https://docs.minio.io/docs/python-client-api-reference#presigned_post_policy>`__

Full Examples
-------------

Full Examples : Bucket Operations
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

-  `list\_buckets.py <https://github.com/minio/minio-py/blob/master/examples/list_buckets.py>`__
-  `list\_objects.py <https://github.com/minio/minio-py/blob/master/examples/list_objects.py>`__
-  `bucket\_exists.py <https://github.com/minio/minio-py/blob/master/examples/bucket_exists.py>`__
-  `make\_bucket.py <https://github.com/minio/minio-py/blob/master/examples/make_bucket.py>`__
-  `remove\_bucket.py <https://github.com/minio/minio-py/blob/master/examples/remove_bucket.py>`__
-  `list\_incomplete\_uploads.py <https://github.com/minio/minio-py/blob/master/examples/list_incomplete_uploads.py>`__
- `remove\_incomplete\_upload.py <https://github.com/minio/minio-py/blob/master/examples/remove_incomplete_upload.py>`__

Full Examples : File Object Operations
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

-  `fput\_object.py <https://github.com/minio/minio-py/blob/master/examples/fput_object.py>`__
-  `fget\_object.py <https://github.com/minio/minio-py/blob/master/examples/fget_object.py>`__

Full Examples : Object Operations
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

-  `put\_object.py <https://github.com/minio/minio-py/blob/master/examples/put_object.py>`__
-  `get\_object.py <https://github.com/minio/minio-py/blob/master/examples/get_object.py>`__
-  `get\_partial\_object.py <https://github.com/minio/minio-py/blob/master/examples/get_partial_object.py>`__
-  `remove\_object.py <https://github.com/minio/minio-py/blob/master/examples/remove_object.py>`__
-  `stat\_object.py <https://github.com/minio/minio-py/blob/master/examples/stat_object.py>`__

Full Examples : Presigned Operations
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

-  `presigned\_get\_object.py <https://github.com/minio/minio-py/blob/master/examples/presigned_get_object.py>`__
-  `presigned\_put\_object.py <https://github.com/minio/minio-py/blob/master/examplespresigned_put_object.py>`__
-  `presigned\_post\_policy.py <https://github.com/minio/minio-py/blob/master/examples/presigned_post_policy.py>`__

Explore Further
---------------

-  `Complete Documentation <https://docs.minio.io>`__
-  `Minio Python SDK API
   Reference <https://docs.minio.io/docs/python-client-api-reference>`__

Contribute
----------

`Contributors Guide <./CONTRIBUTING.md>`__

|PYPI| |Build Status| |Build status|

.. |Gitter| image:: https://badges.gitter.im/Join%20Chat.svg
   :target: https://gitter.im/Minio/minio?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge
.. |PYPI| image:: https://img.shields.io/pypi/v/minio.svg
   :target: https://pypi.python.org/pypi/minio
.. |Build Status| image:: https://travis-ci.org/minio/minio-py.svg
   :target: https://travis-ci.org/minio/minio-py
.. |Build status| image:: https://ci.appveyor.com/api/projects/status/1d05e6nvxcelmrak?svg=true
   :target: https://ci.appveyor.com/project/harshavardhana/minio-py

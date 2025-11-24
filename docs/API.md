# Python Client API Reference [![Slack](https://slack.min.io/slack?type=svg)](https://slack.min.io)

## 1. Constructor

### Minio(*, endpoint: str, access_key: Optional[str] = None, secret_key: Optional[str] = None, session_token: Optional[str] = None, secure: bool = True, region: Optional[str] = None, http_client: Optional[urllib3.PoolManager] = None, credentials: Optional[Provider] = None, cert_check: bool = True)
Initializes a new client object.

__Parameters__

| Param           | Type                                          | Description                                                                      |
|:----------------|:----------------------------------------------|:---------------------------------------------------------------------------------|
| `endpoint`      | _str_                                         | Hostname of a S3 service.                                                        |
| `access_key`    | _Optional[str] = None_                        | (Optional) Access key (aka user ID) of your account in S3 service.               |
| `secret_key`    | _Optional[str] = None_                        | (Optional) Secret Key (aka password) of your account in S3 service.              |
| `session_token` | _Optional[str] = None_                        | (Optional) Session token of your account in S3 service.                          |
| `secure`        | _bool = True_                                 | (Optional) Flag to indicate to use secure (TLS) connection to S3 service or not. |
| `region`        | _Optional[str] = None_                        | (Optional) Region name of buckets in S3 service.                                 |
| `http_client`   | _Optional[urllib3.PoolManager] = None_        | (Optional) Customized HTTP client.                                               |
| `credentials`   | _Optional[minio.credentials.Provider] = None_ | (Optional) Credentials provider of your account in S3 service.                   |
| `cert_check`    | _bool = True_                                 | (Optional) Flag to check on server certificate for HTTPS connection.             |


**NOTE on concurrent usage:** `Minio` object is thread safe when using the Python `threading` library. Specifically, it is **NOT** safe to share it between multiple processes, for example when using `multiprocessing.Pool`. The solution is simply to create a new `Minio` object in each process, and not share it between processes.

__Example__

```py
from minio import Minio

# Create client with anonymous access.
client = Minio(endpoint="play.min.io")

# Create client with access and secret key.
client = Minio(
    endpoint="s3.amazonaws.com",
    access_key="ACCESS-KEY",
    secret_key="SECRET-KEY",
)

# Create client with access key and secret key with specific region.
client = Minio(
    endpoint="play.minio.io:9000",
    access_key="Q3AM3UQ867SPQQA43P2F",
    secret_key="zuf+tfteSlswRu7BJ86wekitnifILbZam1KYY3TG",
    region="my-region",
)

# Create client with custom HTTP client using proxy server.
import urllib3
client = Minio(
    endpoint="SERVER:PORT",
    access_key="ACCESS_KEY",
    secret_key="SECRET_KEY",
    secure=True,
    http_client=urllib3.ProxyManager(
        "https://PROXYSERVER:PROXYPORT/",
        timeout=urllib3.Timeout.DEFAULT_TIMEOUT,
        cert_reqs="CERT_REQUIRED",
        retries=urllib3.Retry(
            total=5,
            backoff_factor=0.2,
            status_forcelist=[500, 502, 503, 504],
        ),
    ),
)
```

| Bucket operations                                           | Object operations                                               |
|:------------------------------------------------------------|:----------------------------------------------------------------|
| [`make_bucket`](#make_bucket)                               | [`append_object`](#append_object)                               |
| [`list_buckets`](#list_buckets)                             | [`get_object`](#get_object)                                     |
| [`bucket_exists`](#bucket_exists)                           | [`put_object`](#put_object)                                     |
| [`remove_bucket`](#remove_bucket)                           | [`copy_object`](#copy_object)                                   |
| [`list_objects`](#list_objects)                             | [`compose_object`](#compose_object)                             |
| [`delete_bucket_cors`](#delete_bucket_cors)                 | [`stat_object`](#stat_object)                                   |
| [`get_bucket_cors`](#get_bucket_cors)                       | [`remove_object`](#remove_object)                               |
| [`set_bucket_cors`](#set_bucket_cors)                       | [`remove_objects`](#remove_objects)                             |
| [`get_bucket_versioning`](#get_bucket_versioning)           | [`fput_object`](#fput_object)                                   |
| [`set_bucket_versioning`](#set_bucket_versioning)           | [`fget_object`](#fget_object)                                   |
| [`delete_bucket_replication`](#delete_bucket_replication)   | [`select_object_content`](#select_object_content)               |
| [`get_bucket_replication`](#get_bucket_replication)         | [`delete_object_tags`](#delete_object_tags)                     |
| [`set_bucket_replication`](#set_bucket_replication)         | [`get_object_tags`](#get_object_tags)                           |
| [`delete_bucket_lifecycle`](#delete_bucket_lifecycle)       | [`set_object_tags`](#set_object_tags)                           |
| [`get_bucket_lifecycle`](#get_bucket_lifecycle)             | [`enable_object_legal_hold`](#enable_object_legal_hold)         |
| [`set_bucket_lifecycle`](#set_bucket_lifecycle)             | [`disable_object_legal_hold`](#disable_object_legal_hold)       |
| [`delete_bucket_tags`](#delete_bucket_tags)                 | [`is_object_legal_hold_enabled`](#is_object_legal_hold_enabled) |
| [`get_bucket_tags`](#get_bucket_tags)                       | [`get_object_retention`](#get_object_retention)                 |
| [`set_bucket_tags`](#set_bucket_tags)                       | [`set_object_retention`](#set_object_retention)                 |
| [`delete_bucket_policy`](#delete_bucket_policy)             | [`presigned_get_object`](#presigned_get_object)                 |
| [`get_bucket_policy`](#get_bucket_policy)                   | [`presigned_put_object`](#presigned_put_object)                 |
| [`set_bucket_policy`](#set_bucket_policy)                   | [`presigned_post_policy`](#presigned_post_policy)               |
| [`delete_bucket_notification`](#delete_bucket_notification) | [`get_presigned_url`](#get_presigned_url)                       |
| [`get_bucket_notification`](#get_bucket_notification)       | [`upload_snowball_objects`](#upload_snowball_objects)           |
| [`set_bucket_notification`](#set_bucket_notification)       | [`prompt_object`](#prompt_object)                               |
| [`listen_bucket_notification`](#listen_bucket_notification) | [`get_object_acl`](#get_object_acl)                             |
| [`delete_bucket_encryption`](#delete_bucket_encryption)     | [`get_object_attributes`](#get_object_attributes)               |
| [`get_bucket_encryption`](#get_bucket_encryption)           | [`put_object_fan_out`](#put_object_fan_out)                     |
| [`set_bucket_encryption`](#set_bucket_encryption)           |                                                                 |
| [`delete_object_lock_config`](#delete_object_lock_config)   |                                                                 |
| [`get_object_lock_config`](#get_object_lock_config)         |                                                                 |
| [`set_object_lock_config`](#set_object_lock_config)         |                                                                 |

## 2. Bucket operations

<a name="make_bucket"></a>

### make_bucket(self, *, bucket_name: str, location: Optional[str] = None, object_lock: bool = False, extra_headers: Optional[HTTPHeaderDict] = None, extra_query_params: Optional[HTTPQueryDict] = None)

Create a bucket with region and object lock.

__Parameters__

| Param                | Type                                           | Description                                |
|----------------------|------------------------------------------------|--------------------------------------------|
| `bucket_name`        | _str_                                          | Name of the bucket.                        |
| `location`           | _Optional[str] = None_                         | Region in which the bucket to be created.  |
| `object_lock`        | _bool = False_                                 | Flag to set object-lock feature.           |
| `extra_headers`      | _Optional[minio.compat.HTTPHeaderDict] = None_ | Extra headers for advanced usage.          |
| `extra_query_params` | _Optional[minio.compat.HTTPQueryDict] = None_  | Extra query parameters for advanced usage. |

__Example__

```py
# Create bucket.
client.make_bucket(bucket_name="my-bucket")

# Create bucket on specific region.
client.make_bucket(bucket_name="my-bucket", location="us-west-1")

# Create bucket with object-lock feature on specific region.
client.make_bucket(bucket_name="my-bucket", location="eu-west-2", object_lock=True)
```

<a name="list_buckets"></a>

### list_buckets(self, *, bucket_region: Optional[str] = None, max_buckets: int = 10000, prefix: Optional[str] = None, extra_headers: Optional[HTTPHeaderDict] = None, extra_query_params: Optional[HTTPQueryDict] = None, ) -> Iterator[ListAllMyBucketsResult.Bucket]

List information of all accessible buckets.

__Parameters__

| Param                | Type                                           | Description                                |
|----------------------|------------------------------------------------|--------------------------------------------|
| `bucket_region`      | _Optional[str] = None_                         | Fetch buckets from the region.             |
| `max_buckets`        | _int = 10000_                                  | Fetch maximum number of buckets.           |
| `prefix`             | _Optional[str] = None_                         | Fetch buckets starts with the prefix.      |
| `extra_headers`      | _Optional[minio.compat.HTTPHeaderDict] = None_ | Extra headers for advanced usage.          |
| `extra_query_params` | _Optional[minio.compat.HTTPQueryDict] = None_  | Extra query parameters for advanced usage. |

__Return Value__

| Return                                                      |
|:------------------------------------------------------------|
| An iterator of _minio.models.ListAllMyBucketsResult.Bucket_ |

__Example__

```py
buckets = client.list_buckets()
for bucket in buckets:
    print(bucket.name, bucket.creation_date)
```

<a name="bucket_exists"></a>

### bucket_exists(self, *, bucket_name: str, region: Optional[str] = None, extra_headers: Optional[HTTPHeaderDict] = None, extra_query_params: Optional[HTTPQueryDict] = None) -> bool

Check if a bucket exists.

__Parameters__

| Param                | Type                                           | Description                                |
|:---------------------|:-----------------------------------------------|:-------------------------------------------|
| `bucket_name`        | _str_                                          | Name of the bucket.                        |
| `region`             | _Optional[str] = None_                         | Region of the bucket to skip auto probing. |
| `extra_headers`      | _Optional[minio.compat.HTTPHeaderDict] = None_ | Extra headers for advanced usage.          |
| `extra_query_params` | _Optional[minio.compat.HTTPQueryDict] = None_  | Extra query parameters for advanced usage. |

__Example__

```py
if client.bucket_exists(bucket_name="my-bucket"):
    print("my-bucket exists")
else:
    print("my-bucket does not exist")
```

<a name="remove_bucket"></a>

### remove_bucket(self, *, bucket_name: str, region: Optional[str] = None, extra_headers: Optional[HTTPHeaderDict] = None, extra_query_params: Optional[HTTPQueryDict] = None)

Remove an empty bucket.

__Parameters__

| Param                | Type                                           | Description                                |
|:---------------------|:-----------------------------------------------|:-------------------------------------------|
| `bucket_name`        | _str_                                          | Name of the bucket.                        |
| `region`             | _Optional[str] = None_                         | Region of the bucket to skip auto probing. |
| `extra_headers`      | _Optional[minio.compat.HTTPHeaderDict] = None_ | Extra headers for advanced usage.          |
| `extra_query_params` | _Optional[minio.compat.HTTPQueryDict] = None_  | Extra query parameters for advanced usage. |

__Example__

```py
client.remove_bucket(bucket_name="my-bucket")
```

<a name="list_objects"></a>

### list_objects(self, *, bucket_name: str, prefix: Optional[str] = None, recursive: bool = False, start_after: Optional[str] = None, include_user_meta: bool = False, include_version: bool = False, use_api_v1: bool = False, use_url_encoding_type: bool = True, fetch_owner: bool = False, region: Optional[str] = None, extra_headers: Optional[HTTPHeaderDict] = None, extra_query_params: Optional[HTTPQueryDict] = None, ) -> Iterator[Object]

Lists object information of a bucket.

__Parameters__

| Param                   | Type                                           | Description                                                  |
|:------------------------|:-----------------------------------------------|:-------------------------------------------------------------|
| `bucket_name`           | _str_                                          | Name of the bucket.                                          |
| `prefix`                | _Optional[str] = None_                         | Object name starts with prefix.                              |
| `recursive`             | _bool = False_                                 | List recursively than directory structure emulation.         |
| `start_after`           | _Optional[str] = None_                         | List objects after this key name.                            |
| `include_user_meta`     | _bool = False_                                 | MinIO specific flag to control to include user metadata.     |
| `include_version`       | _bool = False_                                 | Flag to control whether include object versions.             |
| `use_api_v1`            | _bool = False_                                 | Flag to control to use ListObjectV1 S3 API or not.           |
| `use_url_encoding_type` | _bool = True_                                  | Flag to control whether URL encoding type to be used or not. |
| `fetch_owner`           | _bool = False_                                 | Flag to control to fetch owner information.                  |
| `region`                | _Optional[str] = None_                         | Region of the bucket to skip auto probing.                   |
| `extra_headers`         | _Optional[minio.compat.HTTPHeaderDict] = None_ | Extra headers for advanced usage.                            |
| `extra_query_params`    | _Optional[minio.compat.HTTPQueryDict] = None_  | Extra query parameters for advanced usage.                   |

__Return Value__

| Return                               |
|:-------------------------------------|
| An iterator of _minio.models.Object_ |

__Example__

```py
# List objects information.
objects = client.list_objects(bucket_name="my-bucket")
for obj in objects:
    print(obj)

# List objects information whose names starts with "my/prefix/".
objects = client.list_objects(bucket_name="my-bucket", prefix="my/prefix/")
for obj in objects:
    print(obj)

# List objects information recursively.
objects = client.list_objects(bucket_name="my-bucket", recursive=True)
for obj in objects:
    print(obj)

# List objects information recursively whose names starts with
# "my/prefix/".
objects = client.list_objects(
    bucket_name="my-bucket", prefix="my/prefix/", recursive=True,
)
for obj in objects:
    print(obj)

# List objects information recursively after object name
# "my/prefix/world/1".
objects = client.list_objects(
	bucket_name="my-bucket", recursive=True, start_after="my/prefix/world/1",
)
for obj in objects:
    print(obj)
```

<a name="get_bucket_policy"></a>

### get_bucket_policy(self, *, bucket_name: str, region: Optional[str] = None, extra_headers: Optional[HTTPHeaderDict] = None, extra_query_params: Optional[HTTPQueryDict] = None) -> str

Get bucket policy configuration of a bucket.

__Parameters__

| Param                | Type                                           | Description                                |
|:---------------------|:-----------------------------------------------|:-------------------------------------------|
| `bucket_name`        | _str_                                          | Name of the bucket.                        |
| `region`             | _Optional[str] = None_                         | Region of the bucket to skip auto probing. |
| `extra_headers`      | _Optional[minio.compat.HTTPHeaderDict] = None_ | Extra headers for advanced usage.          |
| `extra_query_params` | _Optional[minio.compat.HTTPQueryDict] = None_  | Extra query parameters for advanced usage. |

__Return Value__

| Param                                       |
|:--------------------------------------------|
| Bucket policy configuration as JSON string. |

__Example__

```py
policy = client.get_bucket_policy(bucket_name="my-bucket")
```

<a name="set_bucket_policy"></a>

### set_bucket_policy(self, *, bucket_name: str, policy: str | bytes, region: Optional[str] = None, extra_headers: Optional[HTTPHeaderDict] = None, extra_query_params: Optional[HTTPQueryDict] = None)

Set bucket policy configuration to a bucket.

__Parameters__

| Param                | Type                                           | Description                                 |
|:---------------------|:-----------------------------------------------|:--------------------------------------------|
| `bucket_name`        | _str_                                          | Name of the bucket.                         |
| `policy`             | _str \| bytes_                                 | Bucket policy configuration as JSON string. |
| `region`             | _Optional[str] = None_                         | Region of the bucket to skip auto probing.  |
| `extra_headers`      | _Optional[minio.compat.HTTPHeaderDict] = None_ | Extra headers for advanced usage.           |
| `extra_query_params` | _Optional[minio.compat.HTTPQueryDict] = None_  | Extra query parameters for advanced usage.  |

__Example__

```py
# Example anonymous read-only bucket policy.
policy = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"AWS": "*"},
            "Action": ["s3:GetBucketLocation", "s3:ListBucket"],
            "Resource": "arn:aws:s3:::my-bucket",
        },
        {
            "Effect": "Allow",
            "Principal": {"AWS": "*"},
            "Action": "s3:GetObject",
            "Resource": "arn:aws:s3:::my-bucket/*",
        },
    ],
}
client.set_bucket_policy(bucket_name="my-bucket", policy=json.dumps(policy))

# Example anonymous read-write bucket policy.
policy = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"AWS": "*"},
            "Action": [
                "s3:GetBucketLocation",
                "s3:ListBucket",
                "s3:ListBucketMultipartUploads",
            ],
            "Resource": "arn:aws:s3:::my-bucket",
        },
        {
            "Effect": "Allow",
            "Principal": {"AWS": "*"},
            "Action": [
                "s3:GetObject",
                "s3:PutObject",
                "s3:DeleteObject",
                "s3:ListMultipartUploadParts",
                "s3:AbortMultipartUpload",
            ],
            "Resource": "arn:aws:s3:::my-bucket/images/*",
        },
    ],
}
client.set_bucket_policy(bucket_name="my-bucket", policy=json.dumps(policy))
```

<a name="delete_bucket_policy"></a>

### delete_bucket_policy(self, *, bucket_name: str, region: Optional[str] = None, extra_headers: Optional[HTTPHeaderDict] = None, extra_query_params: Optional[HTTPQueryDict] = None)

Delete bucket policy configuration of a bucket.

__Parameters__

| Param                | Type                                           | Description                                |
|:---------------------|:-----------------------------------------------|:-------------------------------------------|
| `bucket_name`        | _str_                                          | Name of the bucket.                        |
| `region`             | _Optional[str] = None_                         | Region of the bucket to skip auto probing. |
| `extra_headers`      | _Optional[minio.compat.HTTPHeaderDict] = None_ | Extra headers for advanced usage.          |
| `extra_query_params` | _Optional[minio.compat.HTTPQueryDict] = None_  | Extra query parameters for advanced usage. |

__Example__

```py
client.delete_bucket_policy(bucket_name="my-bucket")
```

<a name="get_bucket_cors"></a>

### get_bucket_cors(self, *, bucket_name: str, region: Optional[str] = None, extra_headers: Optional[HTTPHeaderDict] = None, extra_query_params: Optional[HTTPQueryDict] = None) -> CORSConfig

Get CORS configuration of a bucket.

__Parameters__

| Param                | Type                                           | Description                                |
|:---------------------|:-----------------------------------------------|:-------------------------------------------|
| `bucket_name`        | _str_                                          | Name of the bucket.                        |
| `region`             | _Optional[str] = None_                         | Region of the bucket to skip auto probing. |
| `extra_headers`      | _Optional[minio.compat.HTTPHeaderDict] = None_ | Extra headers for advanced usage.          |
| `extra_query_params` | _Optional[minio.compat.HTTPQueryDict] = None_  | Extra query parameters for advanced usage. |

__Return Value__

| Param                             |
|:----------------------------------|
| _minio.models.CORSConfig_ object. |

__Example__

```py
config = client.get_bucket_cors(bucket_name="my-bucket")
```

<a name="set_bucket_cors"></a>

### set_bucket_cors(self, *, bucket_name: str, config: CORSConfig, region: Optional[str] = None, extra_headers: Optional[HTTPHeaderDict] = None, extra_query_params: Optional[HTTPQueryDict] = None)

Set CORS configuration of a bucket.

__Parameters__

| Param                | Type                                           | Description                                |
|:---------------------|:-----------------------------------------------|:-------------------------------------------|
| `bucket_name`        | _str_                                          | Name of the bucket.                        |
| `config`             | _minio.models.CORSConfig_                      | Cors configuration.                        |
| `region`             | _Optional[str] = None_                         | Region of the bucket to skip auto probing. |
| `extra_headers`      | _Optional[minio.compat.HTTPHeaderDict] = None_ | Extra headers for advanced usage.          |
| `extra_query_params` | _Optional[minio.compat.HTTPQueryDict] = None_  | Extra query parameters for advanced usage. |

__Example__

```py
config = CORSConfig(
    rules=[
        CORSConfig.CORSRule(
            allowed_headers=["*"],
            allowed_methods=["PUT", "POST", "DELETE"],
            allowed_origins=["http://www.example.com"],
            expose_headers=["x-amz-server-side-encryption"],
            max_age_seconds=3000,
        ),
        CORSConfig.CORSRule(
            allowed_methods=["GET"],
            allowed_origins=["*"],
        ),
    ],
)
client.set_bucket_cors(bucket_name="my-bucket", config=config)
```

<a name="delete_bucket_cors"></a>

### delete_bucket_cors(self, *, bucket_name: str, region: Optional[str] = None, extra_headers: Optional[HTTPHeaderDict] = None, extra_query_params: Optional[HTTPQueryDict] = None)

Delete CORS configuration of a bucket.

__Parameters__

| Param                | Type                                           | Description                                |
|:---------------------|:-----------------------------------------------|:-------------------------------------------|
| `bucket_name`        | _str_                                          | Name of the bucket.                        |
| `region`             | _Optional[str] = None_                         | Region of the bucket to skip auto probing. |
| `extra_headers`      | _Optional[minio.compat.HTTPHeaderDict] = None_ | Extra headers for advanced usage.          |
| `extra_query_params` | _Optional[minio.compat.HTTPQueryDict] = None_  | Extra query parameters for advanced usage. |

__Example__

```py
client.delete_bucket_cors(bucket_name="my-bucket")
```

<a name="get_bucket_notification"></a>

### get_bucket_notification(self, *, bucket_name: str, region: Optional[str] = None, extra_headers: Optional[HTTPHeaderDict] = None, extra_query_params: Optional[HTTPQueryDict] = None) -> NotificationConfig

Get notification configuration of a bucket.

__Parameters__

| Param                | Type                                           | Description                                |
|:---------------------|:-----------------------------------------------|:-------------------------------------------|
| `bucket_name`        | _str_                                          | Name of the bucket.                        |
| `region`             | _Optional[str] = None_                         | Region of the bucket to skip auto probing. |
| `extra_headers`      | _Optional[minio.compat.HTTPHeaderDict] = None_ | Extra headers for advanced usage.          |
| `extra_query_params` | _Optional[minio.compat.HTTPQueryDict] = None_  | Extra query parameters for advanced usage. |

__Return Value__

| Param                                     |
|:------------------------------------------|
| _minio.models.NotificationConfig_ object. |

__Example__

```py
config = client.get_bucket_notification(bucket_name="my-bucket")
```

<a name="set_bucket_notification"></a>

### set_bucket_notification(self, *, bucket_name: str, config: NotificationConfig, region: Optional[str] = None, extra_headers: Optional[HTTPHeaderDict] = None, extra_query_params: Optional[HTTPQueryDict] = None)

Set notification configuration of a bucket.

__Parameters__

| Param                | Type                                           | Description                                |
|:---------------------|:-----------------------------------------------|:-------------------------------------------|
| `bucket_name`        | _str_                                          | Name of the bucket.                        |
| `config`             | _minio.models.NotificationConfig_              | Notification configuration.                |
| `region`             | _Optional[str] = None_                         | Region of the bucket to skip auto probing. |
| `extra_headers`      | _Optional[minio.compat.HTTPHeaderDict] = None_ | Extra headers for advanced usage.          |
| `extra_query_params` | _Optional[minio.compat.HTTPQueryDict] = None_  | Extra query parameters for advanced usage. |

__Example__

```py
config = NotificationConfig(
    queue_config_list=[
        QueueConfig(
            queue="QUEUE-ARN-OF-THIS-BUCKET",
            events=["s3:ObjectCreated:*"],
            config_id="1",
            prefix_filter_rule=PrefixFilterRule("abc"),
        ),
    ],
)
client.set_bucket_notification(bucket_name="my-bucket", config=config)
```

<a name="delete_bucket_notification"></a>

### delete_bucket_notification(self, *, bucket_name: str, region: Optional[str] = None, extra_headers: Optional[HTTPHeaderDict] = None, extra_query_params: Optional[HTTPQueryDict] = None)

Delete notification configuration of a bucket. On success, S3 service stops notification of events previously set of the bucket.

__Parameters__

| Param                | Type                                           | Description                                |
|:---------------------|:-----------------------------------------------|:-------------------------------------------|
| `bucket_name`        | _str_                                          | Name of the bucket.                        |
| `region`             | _Optional[str] = None_                         | Region of the bucket to skip auto probing. |
| `extra_headers`      | _Optional[minio.compat.HTTPHeaderDict] = None_ | Extra headers for advanced usage.          |
| `extra_query_params` | _Optional[minio.compat.HTTPQueryDict] = None_  | Extra query parameters for advanced usage. |

__Example__

```py
client.delete_bucket_notification(bucket_name="my-bucket")
```

<a name="listen_bucket_notification"></a>

### listen_bucket_notification(self, *, bucket_name: str, prefix: str = "", suffix: str = "", events: tuple[str, ...] = ('s3:ObjectCreated:*', 's3:ObjectRemoved:*', 's3:ObjectAccessed:*'), region: Optional[str] = None, extra_headers: Optional[HTTPHeaderDict] = None, extra_query_params: Optional[HTTPQueryDict] = None) -> EventIterable

Listen events of object prefix and suffix of a bucket. Caller should iterate returned iterator to read new events.

__Parameters__

| Param                | Type                                                                                    | Description                                 |
|:---------------------|:----------------------------------------------------------------------------------------|:--------------------------------------------|
| `bucket_name`        | _str_                                                                                   | Name of the bucket.                         |
| `prefix`             | _str = ""_                                                                              | Listen events of object starts with prefix. |
| `suffix`             | _str = ""_                                                                              | Listen events of object ends with suffix.   |
| `events`             | _tuple[str, ...] = ('s3:ObjectCreated:*', 's3:ObjectRemoved:*', 's3:ObjectAccessed:*')_ | Events to listen.                           |
| `region`             | _Optional[str] = None_                                                                  | Region of the bucket to skip auto probing.  |
| `extra_headers`      | _Optional[minio.compat.HTTPHeaderDict] = None_                                          | Extra headers for advanced usage.           |
| `extra_query_params` | _Optional[minio.compat.HTTPQueryDict] = None_                                           | Extra query parameters for advanced usage.  |

__Return Value__

| Param                                                  |
|:-------------------------------------------------------|
| Iterator _minio.models.EventIterable_ of event records |

```py
with client.listen_bucket_notification(
    bucket_name="my-bucket",
    prefix="my-prefix/",
    events=["s3:ObjectCreated:*", "s3:ObjectRemoved:*"],
) as events:
    for event in events:
        print(event)
```

<a name="get_bucket_encryption"></a>

### get_bucket_encryption(self, *, bucket_name: str, region: Optional[str] = None, extra_headers: Optional[HTTPHeaderDict] = None, extra_query_params: Optional[HTTPQueryDict] = None) -> Optional[SSEConfig]
Get encryption configuration of a bucket.

__Parameters__

| Param                | Type                                           | Description                                |
|:---------------------|:-----------------------------------------------|:-------------------------------------------|
| `bucket_name`        | _str_                                          | Name of the bucket.                        |
| `region`             | _Optional[str] = None_                         | Region of the bucket to skip auto probing. |
| `extra_headers`      | _Optional[minio.compat.HTTPHeaderDict] = None_ | Extra headers for advanced usage.          |
| `extra_query_params` | _Optional[minio.compat.HTTPQueryDict] = None_  | Extra query parameters for advanced usage. |

__Return Value__

| Param                                      |
|:-------------------------------------------|
| _Optional[minio.models.SSEConfig]_ object. |

__Example__

```py
config = client.get_bucket_encryption(bucket_name="my-bucket")
```

<a name="set_bucket_encryption"></a>

### set_bucket_encryption(self, *, bucket_name: str, config: SSEConfig, region: Optional[str] = None, extra_headers: Optional[HTTPHeaderDict] = None, extra_query_params: Optional[HTTPQueryDict] = None)

Set encryption configuration of a bucket.

__Parameters__

| Param                | Type                                           | Description                                |
|:---------------------|:-----------------------------------------------|:-------------------------------------------|
| `bucket_name`        | _str_                                          | Name of the bucket.                        |
| `config`             | _minio.models.SSEConfig_                       | Server-side encryption configuration.      |
| `region`             | _Optional[str] = None_                         | Region of the bucket to skip auto probing. |
| `extra_headers`      | _Optional[minio.compat.HTTPHeaderDict] = None_ | Extra headers for advanced usage.          |
| `extra_query_params` | _Optional[minio.compat.HTTPQueryDict] = None_  | Extra query parameters for advanced usage. |

__Example__

```py
client.set_bucket_encryption(
    bucket_name="my-bucket", config=SSEConfig(Rule.new_sse_s3_rule()),
)
```

<a name="delete_bucket_encryption"></a>

### delete_bucket_encryption(self, *, bucket_name: str, region: Optional[str] = None, extra_headers: Optional[HTTPHeaderDict] = None, extra_query_params: Optional[HTTPQueryDict] = None)

Delete encryption configuration of a bucket.

__Parameters__

| Param                | Type                                           | Description                                |
|:---------------------|:-----------------------------------------------|:-------------------------------------------|
| `bucket_name`        | _str_                                          | Name of the bucket.                        |
| `region`             | _Optional[str] = None_                         | Region of the bucket to skip auto probing. |
| `extra_headers`      | _Optional[minio.compat.HTTPHeaderDict] = None_ | Extra headers for advanced usage.          |
| `extra_query_params` | _Optional[minio.compat.HTTPQueryDict] = None_  | Extra query parameters for advanced usage. |

__Example__

```py
client.delete_bucket_encryption(bucket_name="my-bucket")
```

<a name="get_bucket_versioning"></a>

### get_bucket_versioning(self, *, bucket_name: str, region: Optional[str] = None, extra_headers: Optional[HTTPHeaderDict] = None, extra_query_params: Optional[HTTPQueryDict] = None) -> VersioningConfig

Get versioning configuration of a bucket.

__Parameters__

| Param                | Type                                           | Description                                |
|:---------------------|:-----------------------------------------------|:-------------------------------------------|
| `bucket_name`        | _str_                                          | Name of the bucket.                        |
| `region`             | _Optional[str] = None_                         | Region of the bucket to skip auto probing. |
| `extra_headers`      | _Optional[minio.compat.HTTPHeaderDict] = None_ | Extra headers for advanced usage.          |
| `extra_query_params` | _Optional[minio.compat.HTTPQueryDict] = None_  | Extra query parameters for advanced usage. |

__Return Value__

| Param                                   |
|:----------------------------------------|
| _minio.models.VersioningConfig_ object. |

__Example__

```py
config = client.get_bucket_versioning(bucket_name="my-bucket")
print(config.status)
```

<a name="set_bucket_versioning"></a>

### set_bucket_versioning(self, *, bucket_name: str, config: VersioningConfig, region: Optional[str] = None, extra_headers: Optional[HTTPHeaderDict] = None, extra_query_params: Optional[HTTPQueryDict] = None)

Set versioning configuration to a bucket.

__Parameters__

| Param                | Type                                           | Description                                |
|:---------------------|:-----------------------------------------------|:-------------------------------------------|
| `bucket_name`        | _str_                                          | Name of the bucket.                        |
| `config`             | _minio.models.VersioningConfig_                | Versioning configuration.                  |
| `region`             | _Optional[str] = None_                         | Region of the bucket to skip auto probing. |
| `extra_headers`      | _Optional[minio.compat.HTTPHeaderDict] = None_ | Extra headers for advanced usage.          |
| `extra_query_params` | _Optional[minio.compat.HTTPQueryDict] = None_  | Extra query parameters for advanced usage. |

__Example__

```py
client.set_bucket_versioning(bucket_name="my-bucket", config=VersioningConfig(ENABLED))
```

<a name="delete_bucket_replication"></a>

### delete_bucket_replication(self, *, bucket_name: str, region: Optional[str] = None, extra_headers: Optional[HTTPHeaderDict] = None, extra_query_params: Optional[HTTPQueryDict] = None)

Delete replication configuration of a bucket.

__Parameters__

| Param                | Type                                           | Description                                |
|:---------------------|:-----------------------------------------------|:-------------------------------------------|
| `bucket_name`        | _str_                                          | Name of the bucket.                        |
| `region`             | _Optional[str] = None_                         | Region of the bucket to skip auto probing. |
| `extra_headers`      | _Optional[minio.compat.HTTPHeaderDict] = None_ | Extra headers for advanced usage.          |
| `extra_query_params` | _Optional[minio.compat.HTTPQueryDict] = None_  | Extra query parameters for advanced usage. |

__Example__

```py
client.delete_bucket_replication(bucket_name="my-bucket")
```

<a name="get_bucket_replication"></a>

### get_bucket_replication(self, *, bucket_name: str, region: Optional[str] = None, extra_headers: Optional[HTTPHeaderDict] = None, extra_query_params: Optional[HTTPQueryDict] = None) -> Optional[ReplicationConfig]

Get replication configuration of a bucket.

__Parameters__

| Param                | Type                                           | Description                                |
|:---------------------|:-----------------------------------------------|:-------------------------------------------|
| `bucket_name`        | _str_                                          | Name of the bucket.                        |
| `region`             | _Optional[str] = None_                         | Region of the bucket to skip auto probing. |
| `extra_headers`      | _Optional[minio.compat.HTTPHeaderDict] = None_ | Extra headers for advanced usage.          |
| `extra_query_params` | _Optional[minio.compat.HTTPQueryDict] = None_  | Extra query parameters for advanced usage. |

| Return                                             |
|:---------------------------------------------------|
| _Optional[minio.models.ReplicationConfig]_ object. |

__Example__

```py
config = client.get_bucket_replication(bucket_name="my-bucket")
```

<a name="set_bucket_replication"></a>

### set_bucket_replication(self, *, bucket_name: str, config: ReplicationConfig, region: Optional[str] = None, extra_headers: Optional[HTTPHeaderDict] = None, extra_query_params: Optional[HTTPQueryDict] = None)

Set replication configuration to a bucket.

__Parameters__

| Param                | Type                                           | Description                                |
|:---------------------|:-----------------------------------------------|:-------------------------------------------|
| `bucket_name`        | _str_                                          | Name of the bucket.                        |
| `config`             | _minio.models.ReplicationConfig_               | Replication configuration.                 |
| `region`             | _Optional[str] = None_                         | Region of the bucket to skip auto probing. |
| `extra_headers`      | _Optional[minio.compat.HTTPHeaderDict] = None_ | Extra headers for advanced usage.          |
| `extra_query_params` | _Optional[minio.compat.HTTPQueryDict] = None_  | Extra query parameters for advanced usage. |

__Example__

```py
config = ReplicationConfig(
    role="REPLACE-WITH-ACTUAL-ROLE",
    rules=[
        Rule(
            destination=Destination(
                "REPLACE-WITH-ACTUAL-DESTINATION-BUCKET-ARN",
            ),
            status=ENABLED,
            delete_marker_replication=DeleteMarkerReplication(
                DISABLED,
            ),
            rule_filter=Filter(
                AndOperator(
                    "TaxDocs",
                    {"key1": "value1", "key2": "value2"},
                ),
            ),
            rule_id="rule1",
            priority=1,
        ),
    ],
)
client.set_bucket_replication(bucket_name="my-bucket", config=config)
```

<a name="delete_bucket_lifecycle"></a>

### delete_bucket_lifecycle(self, *, bucket_name: str, region: Optional[str] = None, extra_headers: Optional[HTTPHeaderDict] = None, extra_query_params: Optional[HTTPQueryDict] = None)

Delete lifecycle configuration of a bucket.

__Parameters__

| Param                | Type                                           | Description                                |
|:---------------------|:-----------------------------------------------|:-------------------------------------------|
| `bucket_name`        | _str_                                          | Name of the bucket.                        |
| `region`             | _Optional[str] = None_                         | Region of the bucket to skip auto probing. |
| `extra_headers`      | _Optional[minio.compat.HTTPHeaderDict] = None_ | Extra headers for advanced usage.          |
| `extra_query_params` | _Optional[minio.compat.HTTPQueryDict] = None_  | Extra query parameters for advanced usage. |

__Example__

```py
client.delete_bucket_lifecycle(bucket_name="my-bucket")
```

<a name="get_bucket_lifecycle"></a>

### get_bucket_lifecycle(self, *, bucket_name: str, region: Optional[str] = None, extra_headers: Optional[HTTPHeaderDict] = None, extra_query_params: Optional[HTTPQueryDict] = None) -> Optional[LifecycleConfig]

Get lifecycle configuration of a bucket.

__Parameters__

| Param                | Type                                           | Description                                |
|:---------------------|:-----------------------------------------------|:-------------------------------------------|
| `bucket_name`        | _str_                                          | Name of the bucket.                        |
| `region`             | _Optional[str] = None_                         | Region of the bucket to skip auto probing. |
| `extra_headers`      | _Optional[minio.compat.HTTPHeaderDict] = None_ | Extra headers for advanced usage.          |
| `extra_query_params` | _Optional[minio.compat.HTTPQueryDict] = None_  | Extra query parameters for advanced usage. |

| Return                                           |
|:-------------------------------------------------|
| _Optional[minio.models.LifecycleConfig]_ object. |


__Example__

```py
config = client.get_bucket_lifecycle(bucket_name="my-bucket")
```

<a name="set_bucket_lifecycle"></a>

### set_bucket_lifecycle(self, *, bucket_name: str, config: LifecycleConfig, region: Optional[str] = None, extra_headers: Optional[HTTPHeaderDict] = None, extra_query_params: Optional[HTTPQueryDict] = None)

Set lifecycle configuration to a bucket.

__Parameters__

| Param                | Type                                           | Description                                |
|:---------------------|:-----------------------------------------------|:-------------------------------------------|
| `bucket_name`        | _str_                                          | Name of the bucket.                        |
| `config`             | _minio.models.LifecycleConfig_                 | Lifecycle configuration.                   |
| `region`             | _Optional[str] = None_                         | Region of the bucket to skip auto probing. |
| `extra_headers`      | _Optional[minio.compat.HTTPHeaderDict] = None_ | Extra headers for advanced usage.          |
| `extra_query_params` | _Optional[minio.compat.HTTPQueryDict] = None_  | Extra query parameters for advanced usage. |

__Example__

```py
config = LifecycleConfig(
    [
        Rule(
            status=ENABLED,
            rule_filter=Filter(prefix="documents/"),
            rule_id="rule1",
            transition=Transition(days=30, storage_class="GLACIER"),
        ),
        Rule(
            status=ENABLED,
            rule_filter=Filter(prefix="logs/"),
            rule_id="rule2",
            expiration=Expiration(days=365),
        ),
    ],
)
client.set_bucket_lifecycle(bucket_name="my-bucket", config=config)
```

<a name="delete_bucket_tags"></a>

### delete_bucket_tags(self, *, bucket_name: str, region: Optional[str] = None, extra_headers: Optional[HTTPHeaderDict] = None, extra_query_params: Optional[HTTPQueryDict] = None)

Delete tags configuration of a bucket.

__Parameters__

| Param                | Type                                           | Description                                |
|:---------------------|:-----------------------------------------------|:-------------------------------------------|
| `bucket_name`        | _str_                                          | Name of the bucket.                        |
| `region`             | _Optional[str] = None_                         | Region of the bucket to skip auto probing. |
| `extra_headers`      | _Optional[minio.compat.HTTPHeaderDict] = None_ | Extra headers for advanced usage.          |
| `extra_query_params` | _Optional[minio.compat.HTTPQueryDict] = None_  | Extra query parameters for advanced usage. |

__Example__

```py
client.delete_bucket_tags(bucket_name="my-bucket")
```

<a name="get_bucket_tags"></a>

### get_bucket_tags(self, *, bucket_name: str, region: Optional[str] = None, extra_headers: Optional[HTTPHeaderDict] = None, extra_query_params: Optional[HTTPQueryDict] = None) -> Optional[Tags]

Get tags configuration of a bucket.

__Parameters__

| Param                | Type                                           | Description                                |
|:---------------------|:-----------------------------------------------|:-------------------------------------------|
| `bucket_name`        | _str_                                          | Name of the bucket.                        |
| `region`             | _Optional[str] = None_                         | Region of the bucket to skip auto probing. |
| `extra_headers`      | _Optional[minio.compat.HTTPHeaderDict] = None_ | Extra headers for advanced usage.          |
| `extra_query_params` | _Optional[minio.compat.HTTPQueryDict] = None_  | Extra query parameters for advanced usage. |

| Return                                |
|:--------------------------------------|
| _Optional[minio.models.Tags]_ object. |

__Example__

```py
tags = client.get_bucket_tags(bucket_name="my-bucket")
```

<a name="set_bucket_tags"></a>

### set_bucket_tags(self, *, bucket_name: str, tags: Tags, region: Optional[str] = None, extra_headers: Optional[HTTPHeaderDict] = None, extra_query_params: Optional[HTTPQueryDict] = None)

Set tags configuration to a bucket.

__Parameters__

| Param                | Type                                           | Description                                |
|:---------------------|:-----------------------------------------------|:-------------------------------------------|
| `bucket_name`        | _str_                                          | Name of the bucket.                        |
| `tags`               | _minio.models.Tags_                            | Tags configuration.                        |
| `region`             | _Optional[str] = None_                         | Region of the bucket to skip auto probing. |
| `extra_headers`      | _Optional[minio.compat.HTTPHeaderDict] = None_ | Extra headers for advanced usage.          |
| `extra_query_params` | _Optional[minio.compat.HTTPQueryDict] = None_  | Extra query parameters for advanced usage. |

__Example__

```py
tags = Tags.new_bucket_tags()
tags["Project"] = "Project One"
tags["User"] = "jsmith"
client.set_bucket_tags(bucket_name="my-bucket", tags=tags)
```

<a name="delete_object_lock_config"></a>

### delete_object_lock_config(self, *, bucket_name: str, region: Optional[str] = None, extra_headers: Optional[HTTPHeaderDict] = None, extra_query_params: Optional[HTTPQueryDict] = None) -> Optional[Tags]

Delete object-lock configuration of a bucket.

__Parameters__

| Param                | Type                                           | Description                                |
|:---------------------|:-----------------------------------------------|:-------------------------------------------|
| `bucket_name`        | _str_                                          | Name of the bucket.                        |
| `region`             | _Optional[str] = None_                         | Region of the bucket to skip auto probing. |
| `extra_headers`      | _Optional[minio.compat.HTTPHeaderDict] = None_ | Extra headers for advanced usage.          |
| `extra_query_params` | _Optional[minio.compat.HTTPQueryDict] = None_  | Extra query parameters for advanced usage. |

__Example__

```py
client.delete_object_lock_config(bucket_name="my-bucket")
```

<a name="get_object_lock_config"></a>

### get_object_lock_config(self, *, bucket_name: str, region: Optional[str] = None, extra_headers: Optional[HTTPHeaderDict] = None, extra_query_params: Optional[HTTPQueryDict] = None) -> ObjectLockConfig

Get object-lock configuration of a bucket.

__Parameters__

| Param                | Type                                           | Description                                |
|:---------------------|:-----------------------------------------------|:-------------------------------------------|
| `bucket_name`        | _str_                                          | Name of the bucket.                        |
| `region`             | _Optional[str] = None_                         | Region of the bucket to skip auto probing. |
| `extra_headers`      | _Optional[minio.compat.HTTPHeaderDict] = None_ | Extra headers for advanced usage.          |
| `extra_query_params` | _Optional[minio.compat.HTTPQueryDict] = None_  | Extra query parameters for advanced usage. |

| Return                                  |
|:----------------------------------------|
| _minio.models.ObjectLockConfig_ object. |

__Example__

```py
config = client.get_object_lock_config(bucket_name="my-bucket")
```

<a name="set_object_lock_config"></a>

### set_object_lock_config(self, *, bucket_name: str, config: ObjectLockConfig, region: Optional[str] = None, extra_headers: Optional[HTTPHeaderDict] = None, extra_query_params: Optional[HTTPQueryDict] = None)

Set object-lock configuration to a bucket.

__Parameters__

| Param                | Type                                           | Description                                |
|:---------------------|:-----------------------------------------------|:-------------------------------------------|
| `bucket_name`        | _str_                                          | Name of the bucket.                        |
| `config`             | _minio.models.ObjectLockConfig_                | Object-Lock configuration.                 |
| `region`             | _Optional[str] = None_                         | Region of the bucket to skip auto probing. |
| `extra_headers`      | _Optional[minio.compat.HTTPHeaderDict] = None_ | Extra headers for advanced usage.          |
| `extra_query_params` | _Optional[minio.compat.HTTPQueryDict] = None_  | Extra query parameters for advanced usage. |

__Example__

```py
config = ObjectLockConfig(GOVERNANCE, 15, DAYS)
client.set_object_lock_config(bucket_name="my-bucket", config=config)
```

## 3. Object operations

<a name="append_object"></a>

### append_object(self, *, bucket_name: str, object_name: str, filename: Optional[str | os.PathLike] = None, stream: Optional[BinaryIO] = None, data: Optional[bytes] = None, length: Optional[int] = None, chunk_size: Optional[int] = None, progress: Optional[ProgressType] = None, region: Optional[str] = None, extra_headers: Optional[HTTPHeaderDict] = None, extra_query_params: Optional[HTTPQueryDict] = None)

Appends data to existing object in a bucket. Only of `filename`, `stream` or `data` must be provided and `length` must be provided if `data` is supplied.

__Parameters__

| Param                | Type                                           | Description                                                |
|:---------------------|:-----------------------------------------------|:-----------------------------------------------------------|
| `bucket_name`        | _str_                                          | Name of the bucket.                                        |
| `object_name`        | _str_                                          | Object name in the bucket.                                 |
| `filename`           | _Optional[str \| os.PathLike] = None_          | Name of file to append.                                    |
| `stream`             | _Optional[io.BinaryIO] = None_                 | An object having callable `read()` returning bytes object. |
| `data`               | _Optional[bytes] = None_                       | Data in byte array.                                        |
| `length`             | _Optional[int] = None_                         | Data length of `data` or `stream`.                         |
| `chunk_size`         | _Optional[int] = None_                         | Chunk size.                                                |
| `progress`           | _Optional[minio.args.ProgressType] = None_     | A progress object.                                         |
| `region`             | _Optional[str] = None_                         | Region of the bucket to skip auto probing.                 |
| `extra_headers`      | _Optional[minio.compat.HTTPHeaderDict] = None_ | Extra headers for advanced usage.                          |
| `extra_query_params` | _Optional[minio.compat.HTTPQueryDict] = None_  | Extra query parameters for advanced usage.                 |

__Return Value__

| Return                                     |
|:-------------------------------------------|
| _minio.models.ObjectWriteResponse_ object. |

__Example__
```py
# Append data.
result = client.append_object(
    bucket_name="my-bucket", 
	object_name="my-object", 
	data=io.BytesIO(b"world"), 
	length=5,
)
print(f"appended {result.object_name} object; etag: {result.etag}")

# Append data in chunks.
with urlopen(
    "https://www.kernel.org/pub/linux/kernel/v6.x/linux-6.13.12.tar.xz",
) as stream:
    result = client.append_object(
        bucket_name="my-bucket", 
        object_name="my-object", 
        stream=stream,
        length=148611164,
        chunk_size=5*1024*1024,
    )
    print(f"appended {result.object_name} object; etag: {result.etag}")

# Append unknown sized data.
with urlopen(
    "https://www.kernel.org/pub/linux/kernel/v6.x/linux-6.14.3.tar.xz",
) as stream:
    result = client.append_object(
        bucket_name="my-bucket", 
        object_name="my-object", 
        stream=stream,
        chunk_size=5*1024*1024,
    )
    print(f"appended {result.object_name} object; etag: {result.etag}")
```

<a name="get_object"></a>

### get_object(self, *, bucket_name: str, object_name: str, version_id: Optional[str] = None, ssec: Optional[SseCustomerKey] = None, offset: int = 0, length: Optional[int] = None, match_etag: Optional[str] = None, not_match_etag: Optional[str] = None, modified_since: Optional[datetime] = None, unmodified_since: Optional[datetime] = None, fetch_checksum: bool = False, region: Optional[str] = None, extra_headers: Optional[HTTPHeaderDict] = None, extra_query_params: Optional[HTTPQueryDict] = None) -> GetObjectResponse

Gets data from offset to length of an object. Returned response should be closed after use to release network resources.

__Parameters__

| Param                | Type                                           | Description                                 |
|:---------------------|:-----------------------------------------------|:--------------------------------------------|
| `bucket_name`        | _str_                                          | Name of the bucket.                         |
| `object_name`        | _str_                                          | Object name in the bucket.                  |
| `version_id`         | _Optional[str] = None_                         | Version-ID of the object.                   |
| `ssec`               | _Optional[minio.sse.SseCustomerKey] = None_    | Server-side encryption customer key.        |
| `offset`             | _int = 0_                                      | Start byte position of object data.         |
| `length`             | _Optional[int] = None_                         | Number of bytes of object data from offset. |
| `match_etag`         | _Optional[str] = None_                         | Match ETag of the object.                   |
| `not_match_etag`     | _Optional[str] = None_                         | None-match ETag of the object.              |
| `modified_since`     | _Optional[datetime.datetime] = None_           | Modified-since of the object.               |
| `unmodified_since`   | _Optional[datetime.datetime] = None_           | Unmodified-since of the object.             |
| `fetch_checksum`     | _bool = False_                                 | Fetch object checksum.                      |
| `region`             | _Optional[str] = None_                         | Region of the bucket to skip auto probing.  |
| `extra_headers`      | _Optional[minio.compat.HTTPHeaderDict] = None_ | Extra headers for advanced usage.           |
| `extra_query_params` | _Optional[minio.compat.HTTPQueryDict] = None_  | Extra query parameters for advanced usage.  |

__Return Value__

| Return                                   |
|:-----------------------------------------|
| _minio.models.GetObjectResponse_ object. |

__Example__

```py
# Get data of an object.
try:
    response = client.get_object(bucket_name="my-bucket", object_name="my-object")
    # Read data from response.
finally:
    response.close()

# Get data of an object of version-ID.
try:
    response = client.get_object(
        bucket_name="my-bucket",
        object_name="my-object",
        version_id="dfbd25b3-abec-4184-a4e8-5a35a5c1174d",
    )
    # Read data from response.
finally:
    response.close()

# Get data of an object from offset and length.
try:
    response = client.get_object(
        bucket_name="my-bucket",
        object_name="my-object",
        offset=512,
        length=1024,
    )
    # Read data from response.
finally:
    response.close()

# Get data of an SSE-C encrypted object.
try:
    response = client.get_object(
        bucket_name="my-bucket",
        object_name="my-object",
        ssec=SseCustomerKey(b"32byteslongsecretkeymustprovided"),
    )
    # Read data from response.
finally:
    response.close()
```

<a name="select_object_content"></a>

### select_object_content(self, *, bucket_name: str, object_name: str, request: SelectObjectContentRequest, region: Optional[str] = None, extra_headers: Optional[HTTPHeaderDict] = None, extra_query_params: Optional[HTTPQueryDict] = None) -> SelectObjectResponse

Select content of an object by SQL expression.

__Parameters__

| Param                | Type                                           | Description                                |
|:---------------------|:-----------------------------------------------|:-------------------------------------------|
| `bucket_name`        | _str_                                          | Name of the bucket.                        |
| `object_name`        | _str_                                          | Object name in the bucket.                 |
| `request`            | _minio.models.SelectObjectContentRequest_      | Select request.                            |
| `region`             | _Optional[str] = None_                         | Region of the bucket to skip auto probing. |
| `extra_headers`      | _Optional[minio.compat.HTTPHeaderDict] = None_ | Extra headers for advanced usage.          |
| `extra_query_params` | _Optional[minio.compat.HTTPQueryDict] = None_  | Extra query parameters for advanced usage. |

__Return Value__

| Return                                      |
|:--------------------------------------------|
| _minio.models.SelectObjectResponse_ object. |

__Example__

```py
with client.select_object_content(
        bucket_name="my-bucket",
        object_name="my-object.csv",
        request=SelectRequest(
            expression="select * from S3Object",
            input_serialization=CSVInputSerialization(),
            output_serialization=CSVOutputSerialization(),
            request_progress=True,
        ),
) as response:
    for data in response.stream():
        print(data.decode())
    print(response.stats())
```

<a name="fget_object"></a>

### fget_object(self, *, bucket_name: str, object_name: str, file_path: str, match_etag: Optional[str] = None, not_match_etag: Optional[str] = None, modified_since: Optional[datetime] = None, unmodified_since: Optional[datetime] = None, fetch_checksum: bool = False, ssec: Optional[SseCustomerKey] = None, version_id: Optional[str] = None, tmp_file_path: Optional[str] = None, progress: Optional[ProgressType] = None, region: Optional[str] = None, extra_headers: Optional[HTTPHeaderDict] = None, extra_query_params: Optional[HTTPQueryDict] = None) -> GetObjectResponse

Downloads data of an object to file.

__Parameters__

| Param                | Type                                           | Description                                 |
|:---------------------|:-----------------------------------------------|:--------------------------------------------|
| `bucket_name`        | _str_                                          | Name of the bucket.                         |
| `object_name`        | _str_                                          | Object name in the bucket.                  |
| `file_path`          | _str_                                          | Name of file to download.                   |
| `version_id`         | _Optional[str] = None_                         | Version-ID of the object.                   |
| `ssec`               | _Optional[minio.sse.SseCustomerKey] = None_    | Server-side encryption customer key.        |
| `offset`             | _int = 0_                                      | Start byte position of object data.         |
| `length`             | _Optional[int] = None_                         | Number of bytes of object data from offset. |
| `tmp_file_path`      | _Optional[str] = None_                         | Path to a temporary file.                   |
| `progress`           | _Optional[minio.args.ProgressType] = None_     | A progress object.                          |
| `match_etag`         | _Optional[str] = None_                         | Match ETag of the object.                   |
| `not_match_etag`     | _Optional[str] = None_                         | None-match ETag of the object.              |
| `modified_since`     | _Optional[datetime.datetime] = None_           | Modified-since of the object.               |
| `unmodified_since`   | _Optional[datetime.datetime] = None_           | Unmodified-since of the object.             |
| `fetch_checksum`     | _bool = False_                                 | Fetch object checksum.                      |
| `region`             | _Optional[str] = None_                         | Region of the bucket to skip auto probing.  |
| `extra_headers`      | _Optional[minio.compat.HTTPHeaderDict] = None_ | Extra headers for advanced usage.           |
| `extra_query_params` | _Optional[minio.compat.HTTPQueryDict] = None_  | Extra query parameters for advanced usage.  |

| Return                                   |
|:-----------------------------------------|
| _minio.models.GetObjectResponse_ object. |

__Example__

```py
# Download data of an object.
client.fget_object(
    bucket_name="my-bucket",
    object_name="my-object",
    file_path="my-filename",
)

# Download data of an object of version-ID.
client.fget_object(
    bucket_name="my-bucket",
    object_name="my-object",
    file_path="my-filename",
    version_id="dfbd25b3-abec-4184-a4e8-5a35a5c1174d",
)

# Download data of an SSE-C encrypted object.
client.fget_object(
    bucket_name="my-bucket",
    object_name="my-object",
    file_path="my-filename",
    ssec=SseCustomerKey(b"32byteslongsecretkeymustprovided"),
)
```

<a name="copy_object"></a>

### copy_object(self, *, bucket_name: str, object_name: str, source: CopySource, sse: Optional[Sse] = None, user_metadata: Optional[HTTPHeaderDict] = None, tags: Optional[Tags] = None, retention: Optional[Retention] = None, legal_hold: bool = False, metadata_directive: Optional[str] = None, tagging_directive: Optional[str] = None, region: Optional[str] = None, extra_headers: Optional[HTTPHeaderDict] = None, extra_query_params: Optional[HTTPQueryDict] = None) -> ObjectWriteResponse

Create an object by server-side copying data from another object. In this API maximum supported source object size is 5GiB.

__Parameters__

| Param                | Type                                           | Description                                                           |
|:---------------------|:-----------------------------------------------|:----------------------------------------------------------------------|
| `bucket_name`        | _str_                                          | Name of the bucket.                                                   |
| `object_name`        | _str_                                          | Object name in the bucket.                                            |
| `source`             | _minio.args.CopySource_                        | Source object information.                                            |
| `sse`                | _Optional[minio.sse.Sse] = None_               | Server-side encryption of destination object.                         |
| `user_metadata`      | _Optional[minio.compat.HTTPHeaderDict] = None_ | Any user-defined metadata to be copied along with destination object. |
| `tags`               | _Optional[minio.models.Tags] = None_           | Tags for destination object.                                          |
| `retention`          | _Optional[minio.models.Retention] = None_      | Retention configuration.                                              |
| `legal_hold`         | _bool = False_                                 | Flag to set legal hold for destination object.                        |
| `metadata_directive` | _Optional[str] = None_                         | Directive used to handle user metadata for destination object.        |
| `tagging_directive`  | _Optional[str] = None_                         | Directive used to handle tags for destination object.                 |
| `region`             | _Optional[str] = None_                         | Region of the bucket to skip auto probing.                            |
| `extra_headers`      | _Optional[minio.compat.HTTPHeaderDict] = None_ | Extra headers for advanced usage.                                     |
| `extra_query_params` | _Optional[minio.compat.HTTPQueryDict] = None_  | Extra query parameters for advanced usage.                            |


__Return Value__

| Return                                     |
|:-------------------------------------------|
| _minio.models.ObjectWriteResponse_ object. |

__Example__

```py
from datetime import datetime, timezone
from minio.commonconfig import REPLACE, CopySource

# copy an object from a bucket to another.
result = client.copy_object(
    bucket_name="my-bucket",
    object_name="my-object",
    CopySource(
        bucket_name="my-sourcebucket",
        object_name="my-sourceobject",
    ),
)
print(result.object_name, result.version_id)

# copy an object with condition.
result = client.copy_object(
    bucket_name="my-bucket",
    object_name="my-object",
    CopySource(
        bucket_name="my-sourcebucket",
        object_name="my-sourceobject",
        modified_since=datetime(2014, 4, 1, tzinfo=timezone.utc),
    ),
)
print(result.object_name, result.version_id)

# copy an object from a bucket with replacing metadata.
user_metadata = {"test_meta_key": "test_meta_value"}
result = client.copy_object(
    bucket_name="my-bucket",
    object_name="my-object",
    CopySource(
        bucket_name="my-sourcebucket",
        object_name="my-sourceobject",
    ),
    user_metadata=user_metadata,
    metadata_directive=REPLACE,
)
print(result.object_name, result.version_id)
```

<a name="compose_object"></a>

### compose_object(self, *, bucket_name: str, object_name: str, sources: list[ComposeSource], sse: Optional[Sse] = None, user_metadata: Optional[HTTPHeaderDict] = None, tags: Optional[Tags] = None, retention: Optional[Retention] = None, legal_hold: bool = False, region: Optional[str] = None, extra_headers: Optional[HTTPHeaderDict] = None, extra_query_params: Optional[HTTPQueryDict] = None) -> ObjectWriteResponse

Create an object by combining data from different source objects using server-side copy.

__Parameters__

| Param                | Type                                           | Description                                                           |
|:---------------------|:-----------------------------------------------|:----------------------------------------------------------------------|
| `bucket_name`        | _str_                                          | Name of the bucket.                                                   |
| `object_name`        | _str_                                          | Object name in the bucket.                                            |
| `sources`            | _list[minio.models.ComposeSource]_             | List of _ComposeSource_ object.                                       |
| `sse`                | _Optional[minio.sse.Sse] = None_               | Server-side encryption of destination object.                         |
| `user_metadata`      | _Optional[minio.compat.HTTPHeaderDict] = None_ | Any user-defined metadata to be copied along with destination object. |
| `tags`               | _Optional[minio.models.Tags] = None_           | Tags for destination object.                                          |
| `retention`          | _Optional[minio.models.Retention] = None_      | Retention configuration.                                              |
| `legal_hold`         | _bool = False_                                 | Flag to set legal hold for destination object.                        |
| `region`             | _Optional[str] = None_                         | Region of the bucket to skip auto probing.                            |
| `extra_headers`      | _Optional[minio.compat.HTTPHeaderDict] = None_ | Extra headers for advanced usage.                                     |
| `extra_query_params` | _Optional[minio.compat.HTTPQueryDict] = None_  | Extra query parameters for advanced usage.                            |


__Return Value__

| Return                                     |
|:-------------------------------------------|
| _minio.models.ObjectWriteResponse_ object. |

__Example__

```py
from minio.commonconfig import ComposeSource
from minio.sse import SseS3

sources = [
    ComposeSource(
        bucket_name="my-job-bucket",
        object_name="my-object-part-one",
    ),
    ComposeSource(
        bucket_name="my-job-bucket",
        object_name="my-object-part-two",
    ),
    ComposeSource(
        bucket_name="my-job-bucket",
        object_name="my-object-part-three",
    ),
]

# Create my-bucket/my-object by combining source object
# list.
result = client.compose_object(
    bucket_name="my-bucket",
    object_name="my-object",
    sources=sources,
)
print(result.object_name, result.version_id)

# Create my-bucket/my-object with user metadata by combining
# source object list.
result = client.compose_object(
    bucket_name="my-bucket",
    object_name="my-object",
    sources=sources,
    user_metadata={"test_meta_key": "test_meta_value"},
)
print(result.object_name, result.version_id)

# Create my-bucket/my-object with user metadata and
# server-side encryption by combining source object list.
client.compose_object(
    bucket_name="my-bucket",
    object_name="my-object",
    sources=sources,
    sse=SseS3(),
)
print(result.object_name, result.version_id)
```

<a name="put_object"></a>

### put_object(self, *, bucket_name: str, object_name: str, data: BinaryIO, length: int, content_type: str = "application/octet-stream", headers: Optional[HTTPHeaderDict] = None, user_metadata: Optional[HTTPHeaderDict] = None, sse: Optional[Sse] = None, progress: Optional[ProgressType] = None, part_size: int = 0, checksum: Optional[Algorithm] = None, num_parallel_uploads: int = 3, tags: Optional[Tags] = None, retention: Optional[Retention] = None, legal_hold: bool = False, region: Optional[str] = None, extra_headers: Optional[HTTPHeaderDict] = None, extra_query_params: Optional[HTTPQueryDict] = None) -> ObjectWriteResponse

Uploads data from a stream to an object in a bucket.

__Parameters__

| Param                  | Type                                           | Description                                               |
|:-----------------------|:-----------------------------------------------|:----------------------------------------------------------|
| `bucket_name`          | _str_                                          | Name of the bucket.                                       |
| `object_name`          | _str_                                          | Object name in the bucket.                                |
| `data`                 | _io.BinaryIO_                                  | An object having callable read() returning bytes object.  |
| `length`               | _int_                                          | Data size; -1 for unknown size and set valid `part_size`. |
| `content_type`         | _str = "application/octet-stream"_             | Content type of the object.                               |
| `headers`              | _Optional[minio.compat.HTTPHeaderDict] = None_ | Additional headers.                                       |
| `user_metadata`        | _Optional[minio.compat.HTTPHeaderDict] = None_ | User metadata of the object.                              |
| `sse`                  | _Optional[minio.sse.Sse] = None_               | Server-side encryption.                                   |
| `progress`             | _Optional[minio.args.ProgressType] = None_     | A progress object.                                        |
| `part_size`            | _int = 0_                                      | Multipart part size.                                      |
| `checksum`             | _Optional[minio.checksum.Algorithm] = None_    | Algorithm for checksum computation.                       |
| `num_parallel_uploads` | _int = 3_                                      | Number of parallel uploads.                               |
| `tags`                 | _Optional[minio.models.Tags] = None_           | Tags for the object.                                      |
| `retention`            | _Optional[minio.models.Retention] = None_      | Retention configuration.                                  |
| `legal_hold`           | _bool = False_                                 | Flag to set legal hold for the object.                    |
| `region`               | _Optional[str] = None_                         | Region of the bucket to skip auto probing.                |
| `extra_headers`        | _Optional[minio.compat.HTTPHeaderDict] = None_ | Extra headers for advanced usage.                         |
| `extra_query_params`   | _Optional[minio.compat.HTTPQueryDict] = None_  | Extra query parameters for advanced usage.                |

__Return Value__

| Return                                     |
|:-------------------------------------------|
| _minio.models.ObjectWriteResponse_ object. |

__Example__
```py
# Upload data.
result = client.put_object(
    bucket_name="my-bucket",
    object_name="my-object",
    data=io.BytesIO(b"hello"),
    length=5,
)
print(
    f"created {result.object_name} object; etag: {result.etag}, "
    f"version-id: {result.version_id}",
)

# Upload unknown sized data.
with urlopen(
    "https://cdn.kernel.org/pub/linux/kernel/v5.x/linux-5.4.81.tar.xz",
) as data:
    result = client.put_object(
        bucket_name="my-bucket",
        object_name="my-object",
        data=data,
        length=-1,
        part_size=10*1024*1024,
    )
    print(
        f"created {result.object_name} object; etag: {result.etag}, "
        f"version-id: {result.version_id}",
    )

# Upload data with content-type.
result = client.put_object(
    bucket_name="my-bucket",
    object_name="my-object",
    data=io.BytesIO(b"hello"),
    length=5,
    content_type="application/csv",
)
print(
    f"created {result.object_name} object; etag: {result.etag}, "
    f"version-id: {result.version_id}",
)

# Upload data with metadata.
result = client.put_object(
    bucket_name="my-bucket",
    object_name="my-object",
    data=io.BytesIO(b"hello"),
    length=5,
    metadata={"My-Project": "one"},
)
print(
    f"created {result.object_name} object; etag: {result.etag}, "
    f"version-id: {result.version_id}",
)

# Upload data with customer key type of server-side encryption.
result = client.put_object(
    bucket_name="my-bucket",
    object_name="my-object",
    data=io.BytesIO(b"hello"),
    length=5,
    sse=SseCustomerKey(b"32byteslongsecretkeymustprovided"),
)
print(
    f"created {result.object_name} object; etag: {result.etag}, "
    f"version-id: {result.version_id}",
)

# Upload data with KMS type of server-side encryption.
result = client.put_object(
    bucket_name="my-bucket",
    object_name="my-object",
    data=io.BytesIO(b"hello"),
    length=5,
    sse=SseKMS("KMS-KEY-ID", {"Key1": "Value1", "Key2": "Value2"}),
)
print(
    f"created {result.object_name} object; etag: {result.etag}, "
    f"version-id: {result.version_id}",
)

# Upload data with S3 type of server-side encryption.
result = client.put_object(
    bucket_name="my-bucket",
    object_name="my-object",
    data=io.BytesIO(b"hello"),
    length=5,
    sse=SseS3(),
)
print(
    f"created {result.object_name} object; etag: {result.etag}, "
    f"version-id: {result.version_id}",
)

# Upload data with tags, retention and legal-hold.
date = datetime.utcnow().replace(
    hour=0, minute=0, second=0, microsecond=0,
) + timedelta(days=30)
tags = Tags(for_object=True)
tags["User"] = "jsmith"
result = client.put_object(
    bucket_name="my-bucket",
    object_name="my-object",
    data=io.BytesIO(b"hello"),
    length=5,
    tags=tags,
    retention=Retention(GOVERNANCE, date),
    legal_hold=True,
)
print(
    f"created {result.object_name} object; etag: {result.etag}, "
    f"version-id: {result.version_id}",
)

# Upload data with progress bar.
result = client.put_object(
    bucket_name="my-bucket",
    object_name="my-object",
    data=io.BytesIO(b"hello"),
    length=5,
    progress=Progress(),
)
print(
    f"created {result.object_name} object; etag: {result.etag}, "
    f"version-id: {result.version_id}",
)
```

<a name="fput_object"></a>

### fput_object(self, *, bucket_name: str, object_name: str, file_path: str, content_type: str = "application/octet-stream", headers: Optional[HTTPHeaderDict] = None, user_metadata: Optional[HTTPHeaderDict] = None, sse: Optional[Sse] = None, progress: Optional[ProgressType] = None, part_size: int = 0, checksum: Optional[Algorithm] = None, num_parallel_uploads: int = 3, tags: Optional[Tags] = None, retention: Optional[Retention] = None, legal_hold: bool = False, region: Optional[str] = None, extra_headers: Optional[HTTPHeaderDict] = None, extra_query_params: Optional[HTTPQueryDict] = None) -> ObjectWriteResponse

Uploads data from a file to an object in a bucket.

__Parameters__

| Param                  | Type                                           | Description                                |
|:-----------------------|:-----------------------------------------------|:-------------------------------------------|
| `bucket_name`          | _str_                                          | Name of the bucket.                        |
| `object_name`          | _str_                                          | Object name in the bucket.                 |
| `file_path`            | _str_                                          | Name of file to upload.                    |
| `content_type`         | _str = "application/octet-stream"_             | Content type of the object.                |
| `headers`              | _Optional[minio.compat.HTTPHeaderDict] = None_ | Additional headers.                        |
| `user_metadata`        | _Optional[minio.compat.HTTPHeaderDict] = None_ | User metadata of the object.               |
| `sse`                  | _Optional[minio.sse.Sse] = None_               | Server-side encryption.                    |
| `progress`             | _Optional[minio.args.ProgressType] = None_     | A progress object.                         |
| `part_size`            | _int = 0_                                      | Multipart part size.                       |
| `checksum`             | _Optional[minio.checksum.Algorithm] = None_    | Algorithm for checksum computation.        |
| `num_parallel_uploads` | _int = 3_                                      | Number of parallel uploads.                |
| `tags`                 | _Optional[minio.models.Tags] = None_           | Tags for the object.                       |
| `retention`            | _Optional[minio.models.Retention] = None_      | Retention configuration.                   |
| `legal_hold`           | _bool = False_                                 | Flag to set legal hold for the object.     |
| `region`               | _Optional[str] = None_                         | Region of the bucket to skip auto probing. |
| `extra_headers`        | _Optional[minio.compat.HTTPHeaderDict] = None_ | Extra headers for advanced usage.          |
| `extra_query_params`   | _Optional[minio.compat.HTTPQueryDict] = None_  | Extra query parameters for advanced usage. |

__Return Value__

| Return                                     |
|:-------------------------------------------|
| _minio.models.ObjectWriteResponse_ object. |

__Example__

```py
# Upload data.
result = client.fput_object(
    bucket_name="my-bucket",
    object_name="my-object",
    file_path="my-filename",
)
print(
    f"created {result.object_name} object; etag: {result.etag}, "
    f"version-id: {result.version_id}",
)

# Upload data with part size.
result = client.fput_object(
    bucket_name="my-bucket",
    object_name="my-object",
    file_path="my-filename",
    part_size=10*1024*1024,
)
print(
    f"created {result.object_name} object; etag: {result.etag}, "
    f"version-id: {result.version_id}",
)

# Upload data with content-type.
result = client.fput_object(
    bucket_name="my-bucket",
    object_name="my-object",
    file_path="my-filename",
    content_type="application/csv",
)
print(
    f"created {result.object_name} object; etag: {result.etag}, "
    f"version-id: {result.version_id}",
)

# Upload data with metadata.
result = client.fput_object(
    bucket_name="my-bucket",
    object_name="my-object",
    file_path="my-filename",
    metadata={"My-Project": "one"},
)
print(
    f"created {result.object_name} object; etag: {result.etag}, "
    f"version-id: {result.version_id}",
)

# Upload data with customer key type of server-side encryption.
result = client.fput_object(
    bucket_name="my-bucket",
    object_name="my-object",
    file_path="my-filename",
    sse=SseCustomerKey(b"32byteslongsecretkeymustprovided"),
)
print(
    f"created {result.object_name} object; etag: {result.etag}, "
    f"version-id: {result.version_id}",
)

# Upload data with KMS type of server-side encryption.
result = client.fput_object(
    bucket_name="my-bucket",
    object_name="my-object",
    file_path="my-filename",
    sse=SseKMS("KMS-KEY-ID", {"Key1": "Value1", "Key2": "Value2"}),
)
print(
    f"created {result.object_name} object; etag: {result.etag}, "
    f"version-id: {result.version_id}",
)

# Upload data with S3 type of server-side encryption.
result = client.fput_object(
    bucket_name="my-bucket",
    object_name="my-object",
    file_path="my-filename",
    sse=SseS3(),
)
print(
    f"created {result.object_name} object; etag: {result.etag}, "
    f"version-id: {result.version_id}",
)

# Upload data with tags, retention and legal-hold.
date = datetime.utcnow().replace(
    hour=0, minute=0, second=0, microsecond=0,
) + timedelta(days=30)
tags = Tags(for_object=True)
tags["User"] = "jsmith"
result = client.fput_object(
    bucket_name="my-bucket",
    object_name="my-object",
    file_path="my-filename",
    tags=tags,
    retention=Retention(GOVERNANCE, date),
    legal_hold=True,
)
print(
    f"created {result.object_name} object; etag: {result.etag}, "
    f"version-id: {result.version_id}",
)

# Upload data with progress bar.
result = client.fput_object(
    bucket_name="my-bucket",
    object_name="my-object",
    file_path="my-filename",
    progress=Progress(),
)
print(
    f"created {result.object_name} object; etag: {result.etag}, "
    f"version-id: {result.version_id}",
)
```

<a name="put_object_fan_out"></a>

### put_object_fan_out(self, *, bucket_name: str, data: BinaryIO, length: int, entries: list[PutObjectFanOutEntry], sse: Optional[Sse] = None, checksum: Optional[Checksum] = None, region: Optional[str] = None, extra_headers: Optional[HTTPHeaderDict] = None, extra_query_params: Optional[HTTPQueryDict] = None) -> PutObjectFanOutResponse

Uploads multiple objects with same content from single stream with optional metadata and tags.

__Parameters__

| Param                | Type                                           | Description                                              |
|:---------------------|:-----------------------------------------------|:---------------------------------------------------------|
| `bucket_name`        | _str_                                          | Name of the bucket.                                      |
| `object_name`        | _str_                                          | Object name in the bucket.                               |
| `data`               | _io.BinaryIO_                                  | An object having callable read() returning bytes object. |
| `length`             | _int_                                          | Size of the data in bytes.                               |
| `entries`            | _list[minio.args.PutObjectFanOutEntry]_        | Objects to be created.                                   |
| `sse`                | _Optional[minio.sse.Sse] = None_               | Server-side encryption.                                  |
| `checksum`           | _Optional[minio.checksum.Algorithm] = None_    | Algorithm for checksum computation.                      |
| `region`             | _Optional[str] = None_                         | Region of the bucket to skip auto probing.               |
| `extra_headers`      | _Optional[minio.compat.HTTPHeaderDict] = None_ | Extra headers for advanced usage.                        |
| `extra_query_params` | _Optional[minio.compat.HTTPQueryDict] = None_  | Extra query parameters for advanced usage.               |


__Return Value__

| Return                                         |
|:-----------------------------------------------|
| _minio.models.PutObjectFanOutResponse_ object. |

__Example__
```py
response = client.put_object_fan_out(
    bucket_name="my-bucket",
    data=io.BytesIO(b"hello"),
    length=5,
    entries=[
        PutObjectFanOutEntry(key="fan-out.0"),
        PutObjectFanOutEntry(
            key="fan-out.1",
            tags={"Project": "Project One", "User": "jsmith"},
        ),
    ],
)
for result in response.results:
    print(
        f"created {result.key} object; etag: {result.etag}, "
        f"version-id: {result.version_id}, ",
        f"error: {result.error}",
    )
```

<a name="stat_object"></a>

### stat_object(self, *, bucket_name: str, object_name: str, version_id: Optional[str] = None, ssec: Optional[SseCustomerKey] = None, offset: int = 0, length: Optional[int] = None, match_etag: Optional[str] = None, not_match_etag: Optional[str] = None, modified_since: Optional[datetime] = None, unmodified_since: Optional[datetime] = None, fetch_checksum: bool = False, region: Optional[str] = None, extra_headers: Optional[HTTPHeaderDict] = None, extra_query_params: Optional[HTTPQueryDict] = None) -> StatObjectResponse:

Get object information and metadata of an object.

__Parameters__

| Param                | Type                                           | Description                                 |
|:---------------------|:-----------------------------------------------|:--------------------------------------------|
| `bucket_name`        | _str_                                          | Name of the bucket.                         |
| `object_name`        | _str_                                          | Object name in the bucket.                  |
| `version_id`         | _Optional[str] = None_                         | Version ID of the object.                   |
| `ssec`               | _Optional[minio.sse.SseCustomerKey] = None_    | Server-side encryption customer key.        |
| `offset`             | _int = 0_                                      | Start byte position of object data.         |
| `length`             | _Optional[int] = None_                         | Number of bytes of object data from offset. |
| `match_etag`         | _Optional[str] = None_                         | Match ETag of the object.                   |
| `not_match_etag`     | _Optional[str] = None_                         | None-match ETag of the object.              |
| `modified_since`     | _Optional[datetime.datetime] = None_           | Modified-since of the object.               |
| `unmodified_since`   | _Optional[datetime.datetime] = None_           | Unmodified-since of the object.             |
| `fetch_checksum`     | _bool = False_                                 | Fetch object checksum.                      |
| `region`             | _Optional[str] = None_                         | Region of the bucket to skip auto probing.  |
| `extra_headers`      | _Optional[minio.compat.HTTPHeaderDict] = None_ | Extra headers for advanced usage.           |
| `extra_query_params` | _Optional[minio.compat.HTTPQueryDict] = None_  | Extra query parameters for advanced usage.  |

__Return Value__

| Return                                    |
|:------------------------------------------|
| _minio.models.StatObjectResponse_ object. |

__Example__

```py
# Get object information.
result = client.stat_object(
    bucket_name="my-bucket",
    object_name="my-object",
)
print(f"last-modified: {result.last_modified}, size: {result.size}")

# Get object information of version-ID.
result = client.stat_object(
    bucket_name="my-bucket",
    object_name="my-object",
    version_id="dfbd25b3-abec-4184-a4e8-5a35a5c1174d",
)
print(f"last-modified: {result.last_modified}, size: {result.size}")

# Get SSE-C encrypted object information.
result = client.stat_object(
    bucket_name="my-bucket",
    object_name="my-object",
    ssec=SseCustomerKey(b"32byteslongsecretkeymustprovided"),
)
print(f"last-modified: {result.last_modified}, size: {result.size}")
```

<a name="remove_object"></a>

### remove_object(self, *, bucket_name: str, object_name: str, version_id: Optional[str] = None, region: Optional[str] = None, extra_headers: Optional[HTTPHeaderDict] = None, extra_query_params: Optional[HTTPQueryDict] = None)

Remove an object.

__Parameters__

| Param                | Type                                           | Description                                |
|:---------------------|:-----------------------------------------------|:-------------------------------------------|
| `bucket_name`        | _str_                                          | Name of the bucket.                        |
| `object_name`        | _str_                                          | Object name in the bucket.                 |
| `version_id`         | _Optional[str] = None_                         | Version ID of the object.                  |
| `region`             | _Optional[str] = None_                         | Region of the bucket to skip auto probing. |
| `extra_headers`      | _Optional[minio.compat.HTTPHeaderDict] = None_ | Extra headers for advanced usage.          |
| `extra_query_params` | _Optional[minio.compat.HTTPQueryDict] = None_  | Extra query parameters for advanced usage. |

__Example__

```py
# Remove object.
client.remove_object(
    bucket_name="my-bucket",
    object_name="my-object",
)

# Remove version of an object.
client.remove_object(
    bucket_name="my-bucket",
    object_name="my-object",
    version_id="dfbd25b3-abec-4184-a4e8-5a35a5c1174d",
)
```

<a name="remove_objects"></a>

### remove_objects(self, *, bucket_name: str, delete_object_list: Iterable[DeleteObject], bypass_governance_mode: bool = False, region: Optional[str] = None, extra_headers: Optional[HTTPHeaderDict] = None, extra_query_params: Optional[HTTPQueryDict] = None) -> Iterator[DeleteError]

Remove multiple objects.

__Parameters__

| Param                    | Type                                           | Description                                |
|:-------------------------|:-----------------------------------------------|:-------------------------------------------|
| `bucket_name`            | _str_                                          | Name of the bucket.                        |
| `delete_object_list`     | _Iterable[minio.models.DeleteRequest.Object]_  | DeleteObject iterable.                     |
| `bypass_governance_mode` | _bool = False_                                 | Bypass Governance retention mode.          |
| `region`                 | _Optional[str] = None_                         | Region of the bucket to skip auto probing. |
| `extra_headers`          | _Optional[minio.compat.HTTPHeaderDict] = None_ | Extra headers for advanced usage.          |
| `extra_query_params`     | _Optional[minio.compat.HTTPQueryDict] = None_  | Extra query parameters for advanced usage. |

__Return Value__

| Return                                              |
|:----------------------------------------------------|
| _Iterator[minio.models.DeleteResult.Error]_ object. |

__Example__

```py
# Remove list of objects.
errors = client.remove_objects(
    bucket_name="my-bucket",
    delete_object_list=[
        DeleteObject(name="my-object1"),
        DeleteObject(name="my-object2"),
        DeleteObject(
            name="my-object3",
            version_id="13f88b18-8dcd-4c83-88f2-8631fdb6250c",
        ),
    ],
)
for error in errors:
    print("error occurred when deleting object", error)

# Remove a prefix recursively.
delete_object_list = map(
    lambda x: DeleteObject(x.object_name),
    client.list_objects(
        bucket_name="my-bucket",
        prefix="my/prefix/",
        recursive=True,
    ),
)
errors = client.remove_objects(
    bucket_name="my-bucket",
    delete_object_list=delete_object_list,
)
for error in errors:
    print("error occurred when deleting object", error)
```

<a name="delete_object_tags"></a>

### delete_object_tags(self, *, bucket_name: str, object_name: str, version_id: Optional[str] = None, region: Optional[str] = None, extra_headers: Optional[HTTPHeaderDict] = None, extra_query_params: Optional[HTTPQueryDict] = None)

Delete tags configuration of an object.

__Parameters__

| Param                | Type                                           | Description                                |
|:---------------------|:-----------------------------------------------|:-------------------------------------------|
| `bucket_name`        | _str_                                          | Name of the bucket.                        |
| `object_name`        | _str_                                          | Object name in the bucket.                 |
| `version_id`         | _Optional[str] = None_                         | Version ID of the object.                  |
| `region`             | _Optional[str] = None_                         | Region of the bucket to skip auto probing. |
| `extra_headers`      | _Optional[minio.compat.HTTPHeaderDict] = None_ | Extra headers for advanced usage.          |
| `extra_query_params` | _Optional[minio.compat.HTTPQueryDict] = None_  | Extra query parameters for advanced usage. |

__Example__

```py
client.delete_object_tags(bucket_name="my-bucket", object_name="my-object")
```

<a name="get_object_attributes"></a>

### get_object_attributes(self, *, bucket_name: str, object_name: str, version_id: Optional[str] = None, ssec: Optional[SseCustomerKey] = None, object_attributes: Optional[list[str]] = None, max_parts: Optional[int] = None, part_number_marker: Optional[int] = None, region: Optional[str] = None, extra_headers: Optional[HTTPHeaderDict] = None, extra_query_params: Optional[HTTPQueryDict] = None) -> Optional[GetObjectAttributesResponse]

Get retention information of an object.

__Parameters__

| Param                | Type                                           | Description                                |
|:---------------------|:-----------------------------------------------|:-------------------------------------------|
| `bucket_name`        | _str_                                          | Name of the bucket.                        |
| `object_name`        | _str_                                          | Object name in the bucket.                 |
| `version_id`         | _Optional[str] = None_                         | Version ID of the object.                  |
| `ssec`               | _Optional[minio.sse.SseCustomerKey] = None_    | Server-side encryption customer key.       |
| `object_attributes`  | _Optional[list[str]] = None_                   | Object attributes.                         |
| `max_parts`          | _Optional[int] = None_                         | Maximum parts to fetch.                    |
| `part_number_marker` | _Optional[int] = None_                         | Part number marker to fetch remaining..    |
| `region`             | _Optional[str] = None_                         | Region of the bucket to skip auto probing. |
| `extra_headers`      | _Optional[minio.compat.HTTPHeaderDict] = None_ | Extra headers for advanced usage.          |
| `extra_query_params` | _Optional[minio.compat.HTTPQueryDict] = None_  | Extra query parameters for advanced usage. |

__Return Value__

| Return                                                       |
|:-------------------------------------------------------------|
| _Optional[minio.models.GetObjectAttributesResponse]_ object. |


__Example__

```py
response = client.get_object_attributes(
    bucket_name="my-bucket",
    object_name="my-object",
)
```

<a name="get_object_acl"></a>

### get_object_acl(self, *, bucket_name: str, object_name: str, version_id: Optional[str] = None, region: Optional[str] = None, extra_headers: Optional[HTTPHeaderDict] = None, extra_query_params: Optional[HTTPQueryDict] = None) -> Optional[GetObjectAclResponse]

Get retention information of an object.

__Parameters__

| Param                | Type                                           | Description                                |
|:---------------------|:-----------------------------------------------|:-------------------------------------------|
| `bucket_name`        | _str_                                          | Name of the bucket.                        |
| `object_name`        | _str_                                          | Object name in the bucket.                 |
| `version_id`         | _Optional[str] = None_                         | Version ID of the object.                  |
| `region`             | _Optional[str] = None_                         | Region of the bucket to skip auto probing. |
| `extra_headers`      | _Optional[minio.compat.HTTPHeaderDict] = None_ | Extra headers for advanced usage.          |
| `extra_query_params` | _Optional[minio.compat.HTTPQueryDict] = None_  | Extra query parameters for advanced usage. |

__Return Value__

| Return                                                |
|:------------------------------------------------------|
| _Optional[minio.models.GetObjectAclResponse]_ object. |


__Example__

```py
response = client.get_object_acl(
    bucket_name="my-bucket",
    object_name="my-object",
)
```

<a name="get_object_tags"></a>

### get_object_tags(self, *, bucket_name: str, object_name: str, version_id: Optional[str] = None, region: Optional[str] = None, extra_headers: Optional[HTTPHeaderDict] = None, extra_query_params: Optional[HTTPQueryDict] = None) -> Optional[Tags]

Get tags configuration of an object.

__Parameters__

| Param                | Type                                           | Description                                |
|:---------------------|:-----------------------------------------------|:-------------------------------------------|
| `bucket_name`        | _str_                                          | Name of the bucket.                        |
| `object_name`        | _str_                                          | Object name in the bucket.                 |
| `version_id`         | _Optional[str] = None_                         | Version ID of the object.                  |
| `region`             | _Optional[str] = None_                         | Region of the bucket to skip auto probing. |
| `extra_headers`      | _Optional[minio.compat.HTTPHeaderDict] = None_ | Extra headers for advanced usage.          |
| `extra_query_params` | _Optional[minio.compat.HTTPQueryDict] = None_  | Extra query parameters for advanced usage. |

| Return                                |
|:--------------------------------------|
| _Optional[minio.models.Tags]_ object. |

__Example__

```py
tags = client.get_object_tags(bucket_name="my-bucket", object_name="my-object")
```

<a name="set_object_tags"></a>

### set_object_tags(self, *, bucket_name: str, object_name: str, tags: Tags, version_id: Optional[str] = None, region: Optional[str] = None, extra_headers: Optional[HTTPHeaderDict] = None, extra_query_params: Optional[HTTPQueryDict] = None)

Set tags configuration to an object.

__Parameters__

| Param                | Type                                           | Description                                |
|:---------------------|:-----------------------------------------------|:-------------------------------------------|
| `bucket_name`        | _str_                                          | Name of the bucket.                        |
| `object_name`        | _str_                                          | Object name in the bucket.                 |
| `tags`               | _minio.models.Tags_                            | Tags configuration.                        |
| `version_id`         | _Optional[str] = None_                         | Version ID of the object.                  |
| `region`             | _Optional[str] = None_                         | Region of the bucket to skip auto probing. |
| `extra_headers`      | _Optional[minio.compat.HTTPHeaderDict] = None_ | Extra headers for advanced usage.          |
| `extra_query_params` | _Optional[minio.compat.HTTPQueryDict] = None_  | Extra query parameters for advanced usage. |

__Example__

```py
tags = Tags.new_object_tags()
tags["Project"] = "Project One"
tags["User"] = "jsmith"
client.set_object_tags(bucket_name="my-bucket", object_name="my-object", tags=tags)
```

<a name="enable_object_legal_hold"></a>

### enable_object_legal_hold(self, *, bucket_name: str, object_name: str, version_id: Optional[str] = None, region: Optional[str] = None, extra_headers: Optional[HTTPHeaderDict] = None, extra_query_params: Optional[HTTPQueryDict] = None)

Enable legal hold on an object.

__Parameters__

| Param                | Type                                           | Description                                |
|:---------------------|:-----------------------------------------------|:-------------------------------------------|
| `bucket_name`        | _str_                                          | Name of the bucket.                        |
| `object_name`        | _str_                                          | Object name in the bucket.                 |
| `version_id`         | _Optional[str] = None_                         | Version ID of the object.                  |
| `region`             | _Optional[str] = None_                         | Region of the bucket to skip auto probing. |
| `extra_headers`      | _Optional[minio.compat.HTTPHeaderDict] = None_ | Extra headers for advanced usage.          |
| `extra_query_params` | _Optional[minio.compat.HTTPQueryDict] = None_  | Extra query parameters for advanced usage. |

__Example__

```py
client.enable_object_legal_hold(bucket_name="my-bucket", object_name="my-object")
```

<a name="disable_object_legal_hold"></a>

### disable_object_legal_hold(self, *, bucket_name: str, object_name: str, version_id: Optional[str] = None, region: Optional[str] = None, extra_headers: Optional[HTTPHeaderDict] = None, extra_query_params: Optional[HTTPQueryDict] = None)

Disable legal hold on an object.

__Parameters__

| Param                | Type                                           | Description                                |
|:---------------------|:-----------------------------------------------|:-------------------------------------------|
| `bucket_name`        | _str_                                          | Name of the bucket.                        |
| `object_name`        | _str_                                          | Object name in the bucket.                 |
| `version_id`         | _Optional[str] = None_                         | Version ID of the object.                  |
| `region`             | _Optional[str] = None_                         | Region of the bucket to skip auto probing. |
| `extra_headers`      | _Optional[minio.compat.HTTPHeaderDict] = None_ | Extra headers for advanced usage.          |
| `extra_query_params` | _Optional[minio.compat.HTTPQueryDict] = None_  | Extra query parameters for advanced usage. |

__Example__

```py
client.disable_object_legal_hold(bucket_name="my-bucket", object_name="my-object")
```

<a name="is_object_legal_hold_enabled"></a>

### is_object_legal_hold_enabled(self, *, bucket_name: str, object_name: str, version_id: Optional[str] = None, region: Optional[str] = None, extra_headers: Optional[HTTPHeaderDict] = None, extra_query_params: Optional[HTTPQueryDict] = None) -> bool

Returns true if legal hold is enabled on an object.

__Parameters__

| Param                | Type                                           | Description                                |
|:---------------------|:-----------------------------------------------|:-------------------------------------------|
| `bucket_name`        | _str_                                          | Name of the bucket.                        |
| `object_name`        | _str_                                          | Object name in the bucket.                 |
| `version_id`         | _Optional[str] = None_                         | Version ID of the object.                  |
| `region`             | _Optional[str] = None_                         | Region of the bucket to skip auto probing. |
| `extra_headers`      | _Optional[minio.compat.HTTPHeaderDict] = None_ | Extra headers for advanced usage.          |
| `extra_query_params` | _Optional[minio.compat.HTTPQueryDict] = None_  | Extra query parameters for advanced usage. |

__Example__

```py
if client.is_object_legal_hold_enabled(
    bucket_name="my-bucket",
    object_name="my-object",
):
    print("legal hold is enabled on my-object")
else:
    print("legal hold is not enabled on my-object")
```

<a name="get_object_retention"></a>

### get_object_retention(self, *, bucket_name: str, object_name: str, version_id: Optional[str] = None, region: Optional[str] = None, extra_headers: Optional[HTTPHeaderDict] = None, extra_query_params: Optional[HTTPQueryDict] = None) -> Optional[Retention]

Get retention information of an object.

__Parameters__

| Param                | Type                                           | Description                                |
|:---------------------|:-----------------------------------------------|:-------------------------------------------|
| `bucket_name`        | _str_                                          | Name of the bucket.                        |
| `object_name`        | _str_                                          | Object name in the bucket.                 |
| `version_id`         | _Optional[str] = None_                         | Version ID of the object.                  |
| `region`             | _Optional[str] = None_                         | Region of the bucket to skip auto probing. |
| `extra_headers`      | _Optional[minio.compat.HTTPHeaderDict] = None_ | Extra headers for advanced usage.          |
| `extra_query_params` | _Optional[minio.compat.HTTPQueryDict] = None_  | Extra query parameters for advanced usage. |

__Return Value__

| Return                                     |
|:-------------------------------------------|
| _Optional[minio.models.Retention]_ object. |


__Example__

```py
config = client.get_object_retention(
    bucket_name="my-bucket",
    object_name="my-object",
)
```

<a name="set_object_retention"></a>

### set_object_retention(self, *, bucket_name: str, object_name: str, config: Retention, version_id: Optional[str] = None, region: Optional[str] = None, extra_headers: Optional[HTTPHeaderDict] = None, extra_query_params: Optional[HTTPQueryDict] = None)

Set retention information to an object.

__Parameters__

| Param                | Type                                           | Description                                |
|:---------------------|:-----------------------------------------------|:-------------------------------------------|
| `bucket_name`        | _str_                                          | Name of the bucket.                        |
| `object_name`        | _str_                                          | Object name in the bucket.                 |
| `config`             | _minio.models.Retention_                       | Retention configuration.                   |
| `version_id`         | _Optional[str] = None_                         | Version ID of the object.                  |
| `region`             | _Optional[str] = None_                         | Region of the bucket to skip auto probing. |
| `extra_headers`      | _Optional[minio.compat.HTTPHeaderDict] = None_ | Extra headers for advanced usage.          |
| `extra_query_params` | _Optional[minio.compat.HTTPQueryDict] = None_  | Extra query parameters for advanced usage. |

__Example__

```py
config = Retention(GOVERNANCE, datetime.utcnow() + timedelta(days=10))
client.set_object_retention(
    bucket_name="my-bucket",
    object_name="my-object",
    config=config,
)
```

<a name="prompt_object"></a>

### prompt_object(self, *, bucket_name: str, object_name: str, prompt: str, lambda_arn: Optional[str] = None, ssec: Optional[SseCustomerKey] = None, version_id: Optional[str] = None, region: Optional[str] = None, extra_headers: Optional[HTTPHeaderDict] = None, extra_query_params: Optional[HTTPQueryDict] = None, **kwargs: Optional[Any]) -> PromptObjectResponse

Prompt an object using natural language.

__Parameters__

| Param                | Type                                           | Description                                                             |
|----------------------|------------------------------------------------|-------------------------------------------------------------------------|
| `bucket_name`        | _str_                                          | Name of the bucket.                                                     |
| `object_name`        | _str_                                          | Object name in the bucket.                                              |
| `prompt`             | _str_                                          | Natural language prompt to interact with the object using the AI model. |
| `lambda_arn`         | _Optional[str] = None_                         | AWS Lambda ARN to use for processing the prompt.                        |
| `ssec`               | _Optional[minio.sse.SseCustomerKey] = None_    | Server-side encryption customer key.                                    |
| `version_id`         | _Optional[str] = None_                         | Version ID of the object.                                               |
| `region`             | _Optional[str] = None_                         | Region of the bucket to skip auto probing.                              |
| `extra_headers`      | _Optional[minio.compat.HTTPHeaderDict] = None_ | Extra headers for advanced usage.                                       |
| `extra_query_params` | _Optional[minio.compat.HTTPQueryDict] = None_  | Extra query parameters for advanced usage.                              |
| `**kwargs`           | _Optional[Any]_                                | Additional parameters for advanced usage.                               |

__Return Value__

| Return                                      |
|:--------------------------------------------|
| _minio.models.PromptObjectResponse_ object. |

__Example__

```py
response = None
try:
    response = client.prompt_object(
        bucket_name="my-bucket",
        object_name="my-object",
        prompt="Describe the object for me",
    )
    # Read data from response
finally:
    if response:
        response.close()
```

<a name="presigned_get_object"></a>

### presigned_get_object(self, *, bucket_name: str, object_name: str, expires: timedelta = timedelta(days=7), request_date: Optional[datetime] = None, version_id: Optional[str] = None, region: Optional[str] = None, extra_query_params: Optional[HTTPQueryDict] = None) -> str

Get presigned URL of an object to download its data with expiry time and custom request parameters.

__Parameters__

| Param                | Type                                              | Description                                |
|:---------------------|:--------------------------------------------------|:-------------------------------------------|
| `bucket_name`        | _str_                                             | Name of the bucket.                        |
| `object_name`        | _str_                                             | Object name in the bucket.                 |
| `expires`            | _datetime.timedelta = datetime.timedelta(days=7)_ | Expiry in seconds.                         |
| `request_date`       | _Optional[datetime.datetime] = None_              | Request time instead of current time.      |
| `version_id`         | _Optional[str] = None_                            | Version ID of the object.                  |
| `region`             | _Optional[str] = None_                            | Region of the bucket to skip auto probing. |
| `extra_query_params` | _Optional[minio.compat.HTTPQueryDict] = None_     | Extra query parameters for advanced usage. |

__Return Value__

| Return     |
|:-----------|
| URL string |

__Example__

```py
# Get presigned URL string to download 'my-object' in
# 'my-bucket' with default expiry (i.e. 7 days).
url = client.presigned_get_object(
    bucket_name="my-bucket", 
    object_name="my-object",
)
print(url)

# Get presigned URL string to download 'my-object' in
# 'my-bucket' with two hours expiry.
url = client.presigned_get_object(
    bucket_name="my-bucket", 
    object_name="my-object",
    expires=timedelta(hours=2),
)
print(url)
```

<a name="presigned_put_object"></a>

### presigned_put_object(self, *, bucket_name: str, object_name: str, expires: timedelta = timedelta(days=7), region: Optional[str] = None, extra_query_params: Optional[HTTPQueryDict] = None) -> str

Get presigned URL of an object to upload data with expiry time and custom request parameters.

__Parameters__

| Param                | Type                                              | Description                                |
|:---------------------|:--------------------------------------------------|:-------------------------------------------|
| `bucket_name`        | _str_                                             | Name of the bucket.                        |
| `object_name`        | _str_                                             | Object name in the bucket.                 |
| `expires`            | _datetime.timedelta = datetime.timedelta(days=7)_ | Expiry in seconds.                         |
| `region`             | _Optional[str] = None_                            | Region of the bucket to skip auto probing. |
| `extra_query_params` | _Optional[minio.compat.HTTPQueryDict] = None_     | Extra query parameters for advanced usage. |

__Return Value__

| Return     |
|:-----------|
| URL string |

__Example__

```py
# Get presigned URL string to upload data to 'my-object' in
# 'my-bucket' with default expiry (i.e. 7 days).
url = client.presigned_put_object(
    bucket_name="my-bucket", 
    object_name="my-object",
)
print(url)

# Get presigned URL string to upload data to 'my-object' in
# 'my-bucket' with two hours expiry.
url = client.presigned_put_object(
    bucket_name="my-bucket", 
    object_name="my-object",
    expires=timedelta(hours=2),
)
print(url)
```

<a name="presigned_post_policy"></a>

### presigned_post_policy(policy: PostPolicy) -> dict[str, str]

Get form-data of PostPolicy of an object to upload its data using POST method.

__Parameters__

| Param    | Type                      | Description  |
|:---------|:--------------------------|:-------------|
| `policy` | _minio.models.PostPolicy_ | Post policy. |

__Return Value__

| Return                                        |
|:----------------------------------------------|
| _dict[str, str]_ object containing form-data. |

__Example__

```py
policy = PostPolicy(
    "my-bucket", datetime.utcnow() + timedelta(days=10),
)
policy.add_starts_with_condition("key", "my/object/prefix/")
policy.add_content_length_range_condition(
    1*1024*1024, 10*1024*1024,
)
form_data = client.presigned_post_policy(policy)
```

<a name="get_presigned_url"></a>

### get_presigned_url(self, *, method: str, bucket_name: str, object_name: str, expires: timedelta = timedelta(days=7), request_date: Optional[datetime] = None, version_id: Optional[str] = None, region: Optional[str] = None, extra_query_params: Optional[HTTPQueryDict] = None) -> str

Get presigned URL of an object for HTTP method, expiry time and custom request parameters.

__Parameters__

| Param                | Type                                              | Description                                |
|:---------------------|:--------------------------------------------------|:-------------------------------------------|
| `method`             | _str_                                             | HTTP method.                               |
| `bucket_name`        | _str_                                             | Name of the bucket.                        |
| `object_name`        | _str_                                             | Object name in the bucket.                 |
| `expires`            | _datetime.timedelta = datetime.timedelta(days=7)_ | Expiry in seconds.                         |
| `request_date`       | _Optional[datetime.datetime] = None_              | Request time instead of current time.      |
| `version_id`         | _Optional[str] = None_                            | Version ID of the object.                  |
| `region`             | _Optional[str] = None_                            | Region of the bucket to skip auto probing. |
| `extra_query_params` | _Optional[minio.compat.HTTPQueryDict] = None_     | Extra query parameters for advanced usage. |

__Return Value__

| Return     |
|:-----------|
| URL string |

__Example__

```py
# Get presigned URL string to delete 'my-object' in
# 'my-bucket' with one day expiry.
url = client.get_presigned_url(
    method="DELETE",
    bucket_name="my-bucket",
    object_name="my-object",
    expires=timedelta(days=1),
)
print(url)

# Get presigned URL string to upload 'my-object' in
# 'my-bucket' with response-content-type as application/json
# and one day expiry.
url = client.get_presigned_url(
    method="PUT",
    bucket_name="my-bucket",
    object_name="my-object",
    expires=timedelta(days=1),
    extra_query_params=HTTPQueryDict({"response-content-type": "application/json"}),
)
print(url)

# Get presigned URL string to download 'my-object' in
# 'my-bucket' with two hours expiry.
url = client.get_presigned_url(
    method="GET",
    bucket_name="my-bucket",
    object_name="my-object",
    expires=timedelta(hours=2),
)
print(url)
```

<a name="upload_snowball_objects"></a>

### upload_snowball_objects(self, *, bucket_name: str, objects: Iterable[SnowballObject], headers: Optional[HTTPHeaderDict] = None, user_metadata: Optional[HTTPHeaderDict] = None, sse: Optional[Sse] = None, tags: Optional[Tags] = None, retention: Optional[Retention] = None, legal_hold: bool = False, staging_filename: Optional[str] = None, compression: bool = False, region: Optional[str] = None, extra_headers: Optional[HTTPHeaderDict] = None, extra_query_params: Optional[HTTPQueryDict] = None) -> ObjectWriteResponse

Uploads multiple objects in a single put call. It is done by creating intermediate TAR file optionally compressed which is uploaded to S3 service.

__Parameters__

| Param                | Type                                           | Description                                        |
|:---------------------|:-----------------------------------------------|:---------------------------------------------------|
| `bucket_name`        | _str_                                          | Name of the bucket.                                |
| `objects`            | _Iterable[minio.models.SnowballObject]_        | An iterable contain snowball object.               |
| `headers`            | _Optional[minio.compat.HTTPHeaderDict] = None_ | Additional headers.                                |
| `user_metadata`      | _Optional[minio.compat.HTTPHeaderDict] = None_ | User metadata.                                     |
| `sse`                | _Optional[minio.sse.Sse] = None_               | Server-side encryption.                            |
| `tags`               | _Optional[minio.models.Tags] = None_           | Tags for the object.                               |
| `retention`          | _Optional[minio.models.Retention] = None_      | Retention configuration.                           |
| `legal_hold`         | _bool = False_                                 | Flag to set legal hold for the object.             |
| `staging_filename`   | _Optional[str] = None_                         | A staging filename to create intermediate tarball. |
| `compression`        | _bool = False_                                 | Flag to compress tarball.                          |
| `region`             | _Optional[str] = None_                         | Region of the bucket to skip auto probing.         |
| `extra_headers`      | _Optional[minio.compat.HTTPHeaderDict] = None_ | Extra headers for advanced usage.                  |
| `extra_query_params` | _Optional[minio.compat.HTTPQueryDict] = None_  | Extra query parameters for advanced usage.         |

__Return Value__

| Return                                     |
|:-------------------------------------------|
| _minio.models.ObjectWriteResponse_ object. |

__Example__

```py
# Upload snowball object.
client.upload_snowball_objects(
    bucket_name="my-bucket",
    objects=[
        SnowballObject(
            object_name="my-object1",
            filename="/etc/hostname",
        ),
        SnowballObject(
            object_name="my-object2",
            data=io.BytesIO(b"hello"),
            length=5,
        ),
        SnowballObject(
            object_name="my-object3",
            data=io.BytesIO(b"world"),
            length=5,
            mod_time=datetime.now(),
        ),
    ],
)
```

## 5. Explore Further

- [MinIO Golang Client SDK Quickstart Guide](https://docs.min.io/enterprise/aistor-object-store/developers/sdk/go/)
- [MinIO Java Client SDK Quickstart Guide](https://docs.min.io/enterprise/aistor-object-store/developers/sdk/java/)
- [MinIO JavaScript Client SDK Quickstart Guide](https://docs.min.io/enterprise/aistor-object-store/developers/sdk/javascript/)

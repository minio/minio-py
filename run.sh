docker build -f Dockerfile-py3-env -t minio-py3-env .
docker run -i -t --rm minio-py3-env /bin/bash


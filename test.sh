docker build -f Dockerfile-py2 -t minio-py2 .
docker run -it --rm --name minio-py2-tests minio-py2

docker build -f Dockerfile-py3 -t minio-py3 .
docker run -it --rm --name minio-py3-tests minio-py3

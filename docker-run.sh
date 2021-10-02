#!/bin/bash

source image_info.txt
ARCH=`uname -m`

# Override version (e.g. pour utiliser x86_64_...)
# VERSION=x86_64_1.29.3
IMAGE_DOCKER=$REPO/${NAME}:${ARCH}_${VERSION}

echo Image docker : $IMAGE_DOCKER

CERT_FOLDER=/home/mathieu/mgdev/certs

export MG_MQ_HOST=mg-dev4.maple.maceroc.com
export CAFILE=/certs/pki.millegrille
export KEYFILE=/certs/pki.maitrecles.key
export CERTFILE=/certs/pki.maitrecles.cert
export MG_MONGO_HOST=mg-dev4.maple.maceroc.com
export RUST_LOG=info
export MG_NOEUD_ID=43eee47d-fc23-4cf5-b359-70069cf06600
export MG_MAITREDESCLES_CA=1

docker run --rm -it \
  --network host \
  -v $CERT_FOLDER:/certs \
  -e CAFILE -e KEYFILE -e CERTFILE \
  -e MG_MQ_HOST -e MG_MONGO_HOST \
  -e MG_MAITREDESCLES_CA \
  -e RUST_LOG \
  $IMAGE_DOCKER

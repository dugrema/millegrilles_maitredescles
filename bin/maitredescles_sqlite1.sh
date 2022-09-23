#!/bin/env bash

# Script d'execution de maitre des cles en mode sqlite1 sans redis

PATH_MILLEGRILLES=/var/opt/millegrilles

export RUST_LOG=warn,millegrilles_maitredescles=info

export CAFILE=$PATH_MILLEGRILLES/configuration/pki.millegrille.cert
export CERTFILE=$PATH_MILLEGRILLES/secrets_partages/pki.certificat_maitredescles.cert
export KEYFILE=$PATH_MILLEGRILLES/secrets_partages/pki.certificat_maitredescles.cle
export MG_MAITREDESCLES_MODE=sqlite
export MG_SQLITE_PATH=$PATH_MILLEGRILLES/sqlite/

mkdir -p $MG_SQLITE_PATH

VARS=`$PATH_MILLEGRILLES/bin/read_config.py`
source $PATH_MILLEGRILLES/bin/source_config.sh

# Re-exporter variables
echo "Instance ID : $INSTANCE_ID"
echo "MQ HOST : $MQ_HOST"
export MG_MQ_HOST=$MQ_HOST
export MG_NOEUD_ID=$INSTANCE_ID

$PATH_MILLEGRILLES/bin/millegrilles_maitredescles

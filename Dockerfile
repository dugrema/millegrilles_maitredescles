FROM ubuntu

ENV APP_FOLDER=/usr/src/app \
    RUST_LOG=warn \
    MG_MQ_HOST=mq \
    MG_MONGO_HOST=mongo \
    CAFILE=/run/secrets/millegrille.cert.pem \
    KEYFILE=/run/secrets/key.pem \
    CERTFILE=/run/secrets/cert.pem \
    MG_FICHIERS_URL=https://fichiers:443

# MG_NOEUD_ID=43eee47d-fc23-4cf5-b359-70069cf06600

WORKDIR $APP_FOLDER

COPY target/release/millegrilles_maitredescles .

CMD ./millegrilles_maitredescles

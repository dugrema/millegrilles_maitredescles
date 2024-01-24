# Application Maitre des clés

## Exposer les ports du middleware

Utiliser le script sous le projet millegrilles.instance.python, repertoire `bin/dev/publish_ports.sh` pour exposer
les ports de redis (6379), MQ (5673) et MongoDB (27017).

Il est aussi possible de les exposer avec la commande :

* `docker service update --publish-add 6379:6379 redis`
* `docker service update --publish-add 5673:5673 mq`
* `docker service update --publish-add 27017:27017 mongo`

## Paramètres

<pre>
CAFILE=/var/opt/millegrilles/configuration/pki.millegrille.cert
CERTFILE=/var/opt/millegrilles/secrets/pki.maitredescles.cert
KEYFILE=/var/opt/millegrilles/secrets/pki.maitredescles.cle
MG_MAITREDESCLES_MODE=CA_partition
MG_MONGO_HOST=localhost
MG_MQ_HOST=localhost
MG_REDIS_PASSWORD_FILE=/var/opt/millegrilles/secrets/passwd.redis.txt
MG_REDIS_URL=rediss://client_rust@localhost:6379#insecure
RUST_LOG=warn,millegrilles_maitredescles=info,millegrilles_maitredescles::maitredescles_partition=trace,millegrilles_maitredescles::maitredescles_ca=trace
</pre>

## Modes de maitre des clés

Il est possible de désactiver les requêtes de rechiffrage avec le paramètres suivant : `DESACTIVER_DECHIFFRAGE=1`. Ce
mode permet d'agir comme backup live des clés de la millegrille. Une instance avec cette option va conserver les clés
normalement et répondre aux requêtes de synchronisation des autres maitres des clés. Elle ne répondra a aucune 
requête client pour rechiffrage de clés. Ceci est idéal pour un backup des clés avec sqlite.

Le paramètre `MG_MAITREDESCLES_MODE` permet de changer le mode de stockage des clés. Par défaut le maitre des
cles agit comme CA et partition (CA_partition) en se connectant à MongoDB. Il est possible d'utiliser une version
qui agit comme partition sans CA sous MongoDB seulement (partition) ou partition avec SQLite (sqlite). 

Modes :
* CA_partition
* partition
* sqlite

Note:

* il doit y avoir exactement une base de données avec le CA par MilleGrille. Une seule instance 3.protege
ou 4.secure peut avoir le mode CA_partition. Les autres doivent utiliser le mode partition ou sqlite.
* Le mode sqlite est moins performant. Il est idéal pour l'installation sur une instance séparée qui sert de backup 
live pour les clés avec `DESACTIVER_DECHIFFRAGE=1`.

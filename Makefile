# Variables
NOM_APP=millegrilles_maitredescles
VERSION?=2026.3
BUILD_NUMBER?=local
VBUILD=$(VERSION).$(BUILD_NUMBER)
DOCKER_IMAGE?=registry.millegrilles.com:5000/millegrilles/maitredescles_rust
DOCKER_IMAGE_NO_PORT=$(shell echo $(DOCKER_IMAGE) | sed 's/:[0-9]*//')
CATALOGUE_ARCHIVE_NAME=$(NOM_APP).$(VBUILD).tar.gz
STAGING_DIR=package_staging

.PHONY: all build docker-build deploy clean package

all: package

# build:
# 	cargo build --release --package $(NOM_APP) --bin $(NOM_APP)
# 	cp "target/release/$(NOM_APP)" "target/release/$(NOM_APP)_x86_64"
# 	gzip -f "target/release/$(NOM_APP)_x86_64"

docker-build:
	docker build -t $(DOCKER_IMAGE):$(VBUILD) .

archive-build:
	rm -rf $(STAGING_DIR)
	mkdir -p $(STAGING_DIR)
	mkdir -p target/release
	cp -r catalogue/* $(STAGING_DIR)/
	sed -i 's/"version": "[^"]*"/"version": "$(VBUILD)"/' $(STAGING_DIR)/metadata.json
	sed -i 's|image: "replace_me"|image: "$(DOCKER_IMAGE_NO_PORT):$(VBUILD)"|' $(STAGING_DIR)/docker-compose.yml
	tar -czf target/release/$(CATALOGUE_ARCHIVE_NAME) -C $(STAGING_DIR) .
	rm -rf $(STAGING_DIR)

package: docker-build archive-build

deploy: package
	docker push $(DOCKER_IMAGE):$(VBUILD)
	echo "Pushing catalogue information to ${DEPLOY_RSYNC_WEBAPP_DEST}/$(NOM_APP)"
	rsync target/release/$(CATALOGUE_ARCHIVE_NAME) ${DEPLOY_RSYNC_WEBAPP_DEST}/$(NOM_APP)
	# ssh fs1 bin/catalogue.py update archives/dev.json --baseurl ${DEPLOY_ARCHIVE_URL}/$(NOM_APP) --archive archives/$(NOM_APP)/${CATALOGUE_ARCHIVE_NAME}
	${DEPLOY_CATALOGUE_UPDATE_COMMAND} --baseurl ${DEPLOY_ARCHIVE_URL}/$(NOM_APP) --archive archives/$(NOM_APP)/${CATALOGUE_ARCHIVE_NAME}

clean:
	cargo clean

MAKEFLAGS += --warn-undefined-variables
SHELL = /bin/bash

SKAFFOLD_VERBOSITY ?= info

TEST_SECRET_BASE_DIR ?= ./temp
TEST_SECRET_COMMENT ?= unit test
GD_PUB_KEY_FILENAME := $(TEST_SECRET_BASE_DIR)/test.key.pub
GD_PRI_KEY_FILENAME := $(TEST_SECRET_BASE_DIR)/test.key
GD_DC_IV_FILENAME := $(TEST_SECRET_BASE_DIR)/dc_iv_file
GD_DC_KEY_FILENAME := $(TEST_SECRET_BASE_DIR)/dc_key_file
GD_HMAC_KEY_FILENAME := $(TEST_SECRET_BASE_DIR)/test-hmac.key
APP_PRIVATE_KEY_FILENAME := $(TEST_SECRET_BASE_DIR)/test-app.key
GHE_REVOCATION_TOKEN_FILENAME := $(TEST_SECRET_BASE_DIR)/test_ghe_revocation_token
GD_IAM_CONF_FILENAME := $(TEST_SECRET_BASE_DIR)/test_iam.conf
GD_GITHUB_CONF =$(TEST_SECRET_BASE_DIR)/github.conf
GD_REVOKER_URLS_CONF := $(TEST_SECRET_BASE_DIR)/test_revoker_urls.conf
GD_EMAIL_CONF := $(TEST_SECRET_BASE_DIR)/email.conf
APP_ID = 0
DAYS_SINCE_REMEDIATION_TO_DELETE = 7

TEST_ENV_VARS := GD_DC_KEY_FILENAME=$(GD_DC_KEY_FILENAME)                \
	GD_DC_IV_FILENAME=$(GD_DC_IV_FILENAME)                               \
	GD_PUB_KEY_FILENAME=$(GD_PUB_KEY_FILENAME)                           \
	GD_PRI_KEY_FILENAME=$(GD_PRI_KEY_FILENAME)                           \
	GD_HMAC_KEY_FILENAME=$(GD_HMAC_KEY_FILENAME)                         \
	APP_PRIVATE_KEY_FILENAME=$(APP_PRIVATE_KEY_FILENAME)                 \
	APP_ID=$(APP_ID)                                                     \
	GHE_REVOCATION_TOKEN_FILENAME=$(GHE_REVOCATION_TOKEN_FILENAME)       \
	GD_IAM_CONF_FILENAME=$(GD_IAM_CONF_FILENAME)                         \
	DAYS_SINCE_REMEDIATION_TO_DELETE=$(DAYS_SINCE_REMEDIATION_TO_DELETE) \
	GD_GITHUB_CONF=${GD_GITHUB_CONF}                                     \
	GD_REVOKER_URLS_CONF=$(GD_REVOKER_URLS_CONF)                         \
	GD_EMAIL_CONF=${GD_EMAIL_CONF}

COVERAGE := pipenv run coverage

# Only set if not defined
VERSION ?= dev

# Trivy related
TRIVY ?= trivy
TRIVY_VERSION := $(shell curl -s "https://api.github.com/repos/aquasecurity/trivy/releases/latest" | grep '"tag_name":' | sed -E 's/.*"v([^"]+)".*/\1/')
TRIVY_OS := $(shell uname | sed 's/Darwin/macOS/' )
TRIVY_ARCH := $(shell uname -m | cut -d_ -f2 )

.PHONY: setup-trivy
setup-trivy:
	curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/master/contrib/install.sh | sudo sh -s -- -b /usr/local/bin
ifdef TRAVIS
	# Scanning Redhat / centOS images requires rpm
	sudo apt update && sudo apt install rpm -y
endif

.PHONY: setup-deploy-tools
setup-deploy-tools:
	curl -Lo container-structure-test https://storage.googleapis.com/container-structure-test/latest/container-structure-test-$(shell uname | tr '[:upper:]' '[:lower:]')-amd64 && sudo install container-structure-test /usr/local/bin/
	container-structure-test version
	curl -Lo skaffold https://storage.googleapis.com/skaffold/releases/latest/skaffold-linux-amd64 && sudo install skaffold /usr/local/bin/
	skaffold version
	curl -s "https://raw.githubusercontent.com/kubernetes-sigs/kustomize/master/hack/install_kustomize.sh" | bash
	sudo install kustomize /usr/local/bin/
	kustomize version

.PHONY: setup
setup: setup-trivy setup-deploy-tools
	pip install --upgrade pip
	pip install pipenv
	PIP_IGNORE_INSTALLED=1 pipenv install --dev --deploy --ignore-pipfile

.PHONY: start-local-test-db
start-local-test-db:
	docker-compose up -d db
	docker-compose ps
	@echo "username/password: postgres/postgres"

.PHONY: stop-local-test-db
stop-local-test-db:
	docker-compose stop db
	docker-compose rm -f db

.PHONY: conn-local-test-db
conn-local-test-db:
	docker-compose run debug

.PHONY: create-unit-test-secrets
create-unit-test-secrets: create-common-test-secrets
	yes | ssh-keygen -q -t rsa -f "$(APP_PRIVATE_KEY_FILENAME)" -N ""  -C "$(TEST_SECRET_COMMENT)" -m pem
	echo "test-token-12345" > "$(GHE_REVOCATION_TOKEN_FILENAME)"
	printf "[iam]\nadmin_apikey = testnotarealtoken123456789" >> "$(GD_IAM_CONF_FILENAME)"
	printf "[github]\ntokens = someRandomTestToken1,someRandomTestToken2,someRandomTestToken3\nhost = github.company.com\nadmin_config = https://%%(host)s/api/v3/repos/admin-org/admin-repo/contents/org_set_config" >> "$(GD_GITHUB_CONF)"
	printf "[revoker-urls]\nartifactory-revocation = http://test\nartifactory-owner-resolution = http://test\ngithub-revocation = http://test\ngithub-owner-resolution = http://test" >> "$(GD_REVOKER_URLS_CONF)"
	printf "[email]\ninternal_email_regex = [A-Z0-9.\-_]+@([A-Z0-9]+\.)*(test.test)$$" >> $(GD_EMAIL_CONF)

.PHONY: create-common-test-secrets
create-common-test-secrets:
	rm -rf $(TEST_SECRET_BASE_DIR)
	mkdir -p $(TEST_SECRET_BASE_DIR)
	yes | ssh-keygen -q -t rsa -f "$(GD_PRI_KEY_FILENAME)" -N ""  -C "$(TEST_SECRET_COMMENT)" -m pem
	ssh-keygen -f "$(GD_PRI_KEY_FILENAME)" -e -m pem > "$(GD_PUB_KEY_FILENAME)"
	cat /dev/random | head -n 256 > "$(GD_HMAC_KEY_FILENAME)"
	dd if=/dev/urandom of=$(GD_DC_KEY_FILENAME) bs=1 count=32
	dd if=/dev/urandom of=$(GD_DC_IV_FILENAME) bs=1 count=16

.PHONY: test-unit-%
# test-unit-<folder_name_under_detect_secrets_stream> to test just the code under specific folder
test-unit-%: create-unit-test-secrets
	$(TEST_ENV_VARS) $(COVERAGE) run -m pytest detect_secrets_stream/$*
	$(COVERAGE) report --include=detect_secrets_stream/$*/* --show-missing

.PHONY: test-unit
test-unit: create-unit-test-secrets start-local-test-db
	@$(TEST_ENV_VARS) $(COVERAGE) run -a -m pytest detect_secrets_stream

.PHONY: coverage-cleanup
coverage-cleanup:
	$(COVERAGE) erase

.PHONY: coverage-report
coverage-report:
	$(COVERAGE) report --include='detect_secrets_stream/*' --show-missing --fail-under 90

.PHONY: test
test: coverage-cleanup test-unit coverage-report

.PHONY: cleanup-test
cleanup-test: stop-local-test-db

.PHONY: quality
quality:
ifdef TRAVIS
	pipenv clean --dry-run
	pipenv clean
endif
	# ignore 41002: coverage <6.0b1 resolved (5.5 installed)! it's part of pytest-cov
	# which does not have a version containing the fix.
	pipenv check --ignore 41002
	pre-commit run --all-files --show-diff-on-failure

.PHONY: start-db_metrics
start-db_metrics:
	@pipenv run python -m detect_secrets_stream.sql_exporter.db_metrics

.PHONY: start-scan_worker
start-scan_worker:
	@pipenv run python -m detect_secrets_stream.scan_worker.app

.PHONY: login
login:
ifndef DOCKER_REG_API_KEY
	$(error env var DOCKER_REG_API_KEY is not set)
endif
ifndef DOCKER_REG_USERNAME
	$(error env var DOCKER_REG_USERNAME is not set)
endif
	# login to the docker registry
	@echo $(DOCKER_REG_API_KEY) | docker login -u $(DOCKER_REG_USERNAME) --password-stdin

.PHONY: build-images
build-images:
	# Skaffold also invokes container image test with container-structure-test
	skaffold build -p build-no-push

.PHONY: quality-images
quality-images:
	# Aggregate return code to allow scan all images before existing
	rc=0;                                                                       \
	for image in $(shell skaffold build -q --dry-run | jq -r .builds[].tag); do \
		$(TRIVY) image --exit-code 1 --ignore-unfixed $${image};                \
		rc=$$((rc+$$?));                                                        \
	done;                                                                       \
	exit $${rc}

.PHONY: deploy
deploy:
	skaffold build

.PHONY: clean
clean:
	skaffold delete -p prod

.PHONY: travis-test
travis-test: test quality cleanup-test build-images quality-images

.PHONY: travis-deploy
travis-deploy: login deploy

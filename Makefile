.DEFAULT_GOAL := help
.PHONY: clean help

PROJECT_NAME ?= spdxvisualizer
PROJECT_SHA ?= $(shell git rev-parse --short HEAD)
DOCKERFILE ?= ${PWD}/Dockerfile
PYTEST_OPTIONS ?= -vvs

image: ## Build the production image
	echo "SHA: ${PROJECT_SHA}"
	docker build \
		-t ${PROJECT_NAME}:latest \
		-t ${PROJECT_NAME}:${PROJECT_SHA} \
		-f ${DOCKERFILE} \
		.

test: image ## Build the test image
	docker run \
		-it \
		--entrypoint pytest \
		${PROJECT_NAME}:${PROJECT_SHA} \
		${PYTEST_OPTIONS}

run: image ## Build the test image
	docker run \
		-it \
		${PROJECT_NAME}:${PROJECT_SHA}


# clean: ## fully delete the build dir

help:
	@sed -rn 's/^([a-zA-Z_-]+):.*?## (.*)$$/"\1" "\2"/p' < $(MAKEFILE_LIST) | xargs printf "make %-20s# %s\n"
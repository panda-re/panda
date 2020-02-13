all: xenial bionic

bionic: Dockerfile_18_04
	docker build . -f Dockerfile_18_04 -t panda:18.04

xenial: Dockerfile_16_04
	docker build . -f Dockerfile_16_04 -t panda:16.04


# To manually push docker containers, run make push after doing a docker login to github registry
push: bionic_push xenial_push

SHA := $(shell git rev-parse HEAD)

bionic_push: Dockerfile_18_04
	docker build . -f Dockerfile_18_04 -t pandare/panda:latest
	docker tag pandare/panda:latest pandare/panda:$(SHA)
	docker push pandare/panda:$(SHA)
	docker push pandare/panda:latest

xenial_push: Dockerfile_16_04
	docker build . -f Dockerfile_16_04 -t pandare/panda_xenial:latest
	docker tag pandare/panda_xenial:latest pandare/panda_xenial:$(SHA)
	docker push pandare/panda_xenial:$(SHA)
	docker push pandare/panda_xenial:latest

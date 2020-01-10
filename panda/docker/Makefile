all: xenial bionic

bionic: Dockerfile_18_04
	docker build . -f Dockerfile_18_04 -t panda:18.04

xenial: Dockerfile_16_04
	docker build . -f Dockerfile_16_04 -t panda:16.04


# To manually push docker containers, run make push after doing a docker login to github registry
push: bionic_push xenial_push

SHA := $(shell git rev-parse HEAD)

bionic_push: Dockerfile_18_04
	docker build . -f Dockerfile_18_04 -t docker.pkg.github.com/panda-re/panda/panda_bionic:latest
	docker tag docker.pkg.github.com/panda-re/panda/panda_bionic:latest docker.pkg.github.com/panda-re/panda/panda_bionic:$(SHA)
	docker push docker.pkg.github.com/panda-re/panda/panda_bionic:$(SHA)
	docker push docker.pkg.github.com/panda-re/panda/panda_bionic:latest

xenial_push: Dockerfile_16_04
	docker build . -f Dockerfile_16_04 -t docker.pkg.github.com/panda-re/panda/panda_xenial:latest
	docker tag docker.pkg.github.com/panda-re/panda/panda_xenial:latest docker.pkg.github.com/panda-re/panda/panda_xenial:$(SHA)
	docker push docker.pkg.github.com/panda-re/panda/panda_xenial:$(SHA)
	docker push docker.pkg.github.com/panda-re/panda/panda_xenial:latest

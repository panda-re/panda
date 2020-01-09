all: xenial bionic

bionic: Dockerfile_18_04
	docker build . -f Dockerfile_18_04 -t panda:18.04

xenial: Dockerfile_16_04
	docker build . -f Dockerfile_16_04 -t panda:16.04

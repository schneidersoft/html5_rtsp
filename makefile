PODMAN = podman

all:
	gcc -Wall -Isrc/ src/wsproxy.c src/cencode.c src/sha1.c -o wsproxy -lpthread

network:
	$(PODMAN) network create wsp-network

web:
	$(PODMAN) run --rm -ti --name server --network wsp-network -v ./nginx.conf:/etc/nginx/nginx.conf -v ./:/usr/share/nginx/html:ro -p 8080:80 docker.io/nginx

container:
	$(PODMAN) build -t wsp:latest .

wsp:
	$(PODMAN) run --rm -ti --name wsp --network wsp-network wsp:latest

alpine:
	$(PODMAN) run --rm -ti --name alpine --network wsp-network docker.io/alpine

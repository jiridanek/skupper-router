DOCKER=${DOCKER:-podman}

${DOCKER} build --platform linux/arm64/v8 -t hello-world:v1.0.0-linux-arm64 .

--platform linux/amd64

linux/s390x

${DOCKER} manifest create \
  phx.ocir.io/<namespace>/hello-world:v1.0.0 \
  phx.ocir.io/<namespace>hello-world:v1.0.0-linux-arm64 \
  phx.ocir.io/<namespace>hello-world:v1.0.0-linux-amd64
${DOCKER} manifest push

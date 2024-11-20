# podman build -t crimson-forge .
# podman run --rm -v $(pwd):/root/crimson-forge -ti crimson-forge:latest /bin/bash
FROM registry.fedoraproject.org/fedora:32
USER root

# install dependencies
RUN dnf install --assumeyes cmake pipenv wget z3-libs

WORKDIR /root/crimson-forge
COPY .  .
RUN pipenv install

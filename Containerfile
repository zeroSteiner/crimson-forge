# podman build -t crimson-forge .
# podman run --rm -v $(pwd):/opt/crimson-forge -ti crimson-forge:latest /bin/bash
FROM registry.fedoraproject.org/fedora:34
USER root

# install dependencies
RUN dnf install --assumeyes cmake git pipenv python wget z3-libs

WORKDIR /opt/crimson-forge
COPY .  .
RUN pipenv install --system && git clean --force -dx

# podman build -t crimson-forge .
# podman run --rm -v $(pwd):/opt/crimson-forge -ti crimson-forge:latest /bin/bash
FROM registry.fedoraproject.org/fedora:40
USER root

# install dependencies
RUN dnf install --assumeyes cmake git python python-pip wget z3-libs

WORKDIR /opt/crimson-forge
COPY .  .
RUN python -m pip install pipenv && pipenv install --system && git clean --force -dx

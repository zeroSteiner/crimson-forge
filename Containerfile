# podman build -t crimson-forge .
# podman run --rm -v $(pwd):/opt/crimson-forge:z -ti crimson-forge:latest /bin/bash
FROM registry.fedoraproject.org/fedora:40
USER root

# install dependencies
RUN dnf install --assumeyes cmake git python uv wget z3-libs

ENV UV_PROJECT_ENVIRONMENT=/opt/venv
ENV PATH="/opt/venv/bin:$PATH"

WORKDIR /opt/crimson-forge
COPY .  .
RUN uv sync && git clean --force -dx

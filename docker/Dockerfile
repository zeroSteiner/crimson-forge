FROM ubuntu:20.04
MAINTAINER Spencer McIntyre <zeroSteiner@gmail.com> (@zeroSteiner)

ENV DEBIAN_FRONTEND noninteractive
ENV SHELL           /bin/bash

RUN apt-get update && \
    apt-get dist-upgrade -y && \
    apt-get install -y pipenv python3 && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*
RUN ln -s /usr/bin/python3 /usr/bin/python

ADD . /crimson-forge
WORKDIR /crimson-forge
RUN if [ ! -e "requirements.txt" ]; then \
        pipenv lock -r > requirements.txt; \
    fi
RUN python3 -m pip install -r requirements.txt

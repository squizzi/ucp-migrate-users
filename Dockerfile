FROM jfloff/alpine-python:2.7-slim

MAINTAINER Kyle Squizzato: 'kyle.squizzato@docker.com'

WORKDIR /migrate/

RUN pip install --upgrade \
    pip \
    requests \
    colored \
    jsondiff

COPY . /migrate/

ENTRYPOINT /migrate/migrate.py

FROM jfloff/alpine-python:2.7-slim

MAINTAINER Kyle Squizzato: 'kyle.squizzato@docker.com'

WORKDIR /

RUN pip install --upgrade \
    pip \
    requests \
    colored \
    jsondiff \
    validators

COPY ./migrate.py /

ENTRYPOINT ["python", "./migrate.py"]

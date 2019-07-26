FROM docker:19-dind

MAINTAINER Kyle Squizzato: 'kyle.squizzato@docker.com'

WORKDIR /

RUN apk update && apk add python3
RUN python3 -m ensurepip
RUN pip3 install --upgrade \
    docker \
    pip \
    requests \
    colored \
    jsondiff \
    validators

COPY ./migrate.py /

ENTRYPOINT ["python3", "./migrate.py"]

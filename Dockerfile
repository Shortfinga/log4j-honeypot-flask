FROM python:slim

MAINTAINER Randy Pargman "randy.pargman@binarydefense.com"

RUN useradd log4jhp

WORKDIR /home/log4jhp

RUN apt-get update -y && \
    apt-get install -y python3-pip python-dev
    
RUN apt-get install build-essential python3-dev python2.7-dev \
    libldap2-dev libsasl2-dev slapd ldap-utils tox \
    lcov valgrind

# We copy just the requirements.txt first to leverage Docker cache
COPY requirements.txt requirements.txt
RUN mkdir payloads
ADD ./payloads /home/log4jhp/payloads
RUN python3 -m venv venv
RUN venv/bin/pip install -r requirements.txt

COPY app app
COPY boot.sh ./
RUN chmod +x boot.sh
RUN chown -R log4jhp:log4jhp ./
USER log4jhp

EXPOSE 80
ENTRYPOINT [ "./boot.sh" ]

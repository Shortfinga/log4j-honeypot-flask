FROM python:3.9

RUN pip install pipenv

RUN apt-get update && apt-get install -y \
    libldap2-dev \
    libsasl2-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /honeypot
COPY . .
ENV PIPENV_VENV_IN_PROJECT=1
RUN pipenv sync

ENTRYPOINT [".venv/bin/gunicorn"]

# log4j-honeypot-flask
Internal network honeypot for detecting if an attacker or insider threat scans
your network for log4j CVE-2021-44228

This can be installed on a workstation or server, either by running the Python
app/app.py script directly (you'll need python3, Flask, and Requests) or as a
Docker container.

Configure `config.ini`.

Important Note: This is a LOW-INTERACTION honeypot meant for internal active
defense. It is not supposed to be vulnerable or let attackers get into
anything.

# Example running via command line (**DEBIAN**):

```
sudo apt-get update
sudo apt-get install python3 python3-pip
pip install pipenv
pipenv install
pipenv run gunicorn
```

# Running Docker

```
docker build -t honeypot .
docker run -p 80:8080 \
    -v /dir/where/you/want/the/payloads:/honeypot/payloads \
    -v /dir/where/you/want/the/logs/log.json:/honeypot/log.json \  # This is optional
    honeypot
```

## With custom 
```
docker build -t honeypot .
cp config.ini.dist config.ini
vim config.ini
docker run -p 80:8080 \
    -v /dir/where/you/want/the/payloads:/honeypot/payloads \
    -v /dir/where/you/want/the/logs/log.json:/honeypot/log.json \  # If you haven't disabled it...
    -v $(pwd)/config.ini:/honeypot/config.ini \
    honeypot
```

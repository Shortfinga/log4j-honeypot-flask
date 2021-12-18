# log4j-honeypot-flask
Internal network honeypot for detecting if an attacker or insider threat scans your network for log4j CVE-2021-44228

This can be installed on a workstation or server, either by running the Python app/app.py script directly (you'll need python3, Flask, and Requests) or as a Docker container.

Configure `config.ini`.

Important Note: This is a LOW-INTERACTION honeypot meant for internal active defense. It is not supposed to be vulnerable or let attackers get into anything.

# Example running via command line (**DEBIAN**):

```
sudo apt-get update
sudo apt-get install -y build-essential python3-dev python2.7-dev libldap2-dev libsasl2-dev slapd ldap-utils tox lcov valgrind
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python3 app/app.py
```

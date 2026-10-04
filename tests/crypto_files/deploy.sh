#!/bin/sh
openssl genrsa -out k.pem 1024
openssl req -newkey rsa:4096 -x509 -out c.pem
ssh-keygen -t rsa -b 1024 -f id

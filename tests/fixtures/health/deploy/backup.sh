#!/bin/sh
# A backup inherits the longest lifetime it contains — here seventy years.
openssl genrsa -out /backup/key.pem 4096

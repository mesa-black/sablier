#!/bin/sh
# Fixture: an encrypted backup, of the kind found on a server.
openssl genrsa -out /etc/backup/key.pem 2048
pg_dump -Fc app | openssl enc -aes-256-cbc -pbkdf2 -pass env:BACKUP_KEY > dump.enc
ssh-keygen -t rsa -b 4096 -f /root/.ssh/offsite

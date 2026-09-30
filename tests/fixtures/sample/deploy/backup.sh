#!/bin/sh
# Jeu d'essai : sauvegarde chiffrée, du genre qu'on trouve sur un serveur.
openssl genrsa -out /etc/backup/key.pem 2048
pg_dump -Fc app | openssl enc -aes-256-cbc -pbkdf2 -pass env:BACKUP_KEY > dump.enc
ssh-keygen -t rsa -b 4096 -f /root/.ssh/offsite

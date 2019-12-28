#!/bin/bash
rm *.pem
#openssl genrsa -out keys/ca_key.pem 2048;
for i in `seq 1 10`; do
    openssl genrsa -out rsakey_${i}.pem 2048;
done;

for i in `seq 1 10`; do
  openssl dhparam -out dhparam_${i}.pem 1024;
  openssl genpkey -paramfile dhparam_${i}.pem -out dhkey_${i}.pem;
  openssl pkey -in dhkey_${i}.pem -pubout -out dhpubkey_${i}.pem;
done;
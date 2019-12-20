#!/bin/bash
rm *.pem
openssl genrsa -out keys/ca_key.pem 2048;
for i in `seq 1 10`; do
    openssl genrsa -out ${i}_key.pem 2048;
done;

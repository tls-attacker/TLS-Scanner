#!/bin/bash

openssl genrsa -out rootv1.pem 2048;
openssl genrsa -out rootv3.pem 2048;
openssl ecparam -out ecrootv3_param.pem -name secp384r1;
openssl genpkey -paramfile ecrootv3_param.pem -out ecrootv3.pem;
openssl pkey -in ecrootv3.pem -pubout -out ecrootv3_pub.pem;
openssl dsaparam -out dsaparam_rootv3.pem 1024;
openssl gendsa -out dsarootv3.pem dsaparam_rootv3.pem;


openssl genrsa -3 -out rsakey_weak512.pem 512;

for i in `seq 1 10`; do
  openssl genrsa -out rsakey_${i}.pem 2048;
done;

for i in `seq 1 10`; do
  openssl dhparam -out dhparam_${i}.pem 1024;
  openssl genpkey -paramfile dhparam_${i}.pem -out dhkey_${i}.pem;
  openssl pkey -in dhkey_${i}.pem -pubout -out dhpubkey_${i}.pem;
done;

for i in `seq 1 10`; do
  openssl dsaparam -out dsaparam_${i}.pem 1024;
  openssl gendsa -out dsakey_${i}.pem dsaparam_${i}.pem;
done;

for i in `seq 1 5`; do
  openssl ecparam -out ecparam_secp256r1_${i}.pem -name secp256r1;
  openssl genpkey -paramfile ecparam_secp256r1_${i}.pem -out eckey_secp256r1_${i}.pem;
  openssl pkey -in eckey_secp256r1_${i}.pem -pubout -out ecpubkey_secp256r1_${i}.pem;
done;
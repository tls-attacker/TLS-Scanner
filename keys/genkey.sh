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

for named_curve in secp160k1 secp160r1 secp160r2 secp192k1 secp224k1 secp224r1 secp256k1 secp256r1 secp384r1 secp521r1 sect163k1 sect163r1 sect163r2 sect193r1 sect193r2 sect233k1 sect233r1 sect239k1 sect283k1 sect283r1 sect409k1 sect409r1 sect571k1 sect571r1; do
  openssl ecparam -out ecparam_${named_curve}.pem -name ${named_curve};
  openssl genpkey -paramfile ecparam_${named_curve}.pem -out eckey_${named_curve}.pem;
  openssl pkey -in eckey_${named_curve}.pem -pubout -out ecpubkey_${named_curve}.pem;
done;
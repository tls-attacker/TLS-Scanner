# TLS-Scanner

![GitHub release (latest by date)](https://img.shields.io/github/v/release/tls-attacker/TLS-Scanner)
![licence](https://img.shields.io/badge/License-Apachev2-brightgreen.svg)
[![Build Status](https://hydrogen.cloud.nds.rub.de/buildStatus/icon.svg?job=TLS-Scanner)](https://hydrogen.cloud.nds.rub.de/job/TLS-Scanner/)

TLS-Scanner is a tool created by the Chair for Network and Data Security from the Ruhr-University Bochum to assist pentesters and security researchers in the evaluation of TLS Server configurations. 

**Please note:**  *TLS-Scanner is a research tool intended for TLS developers, pentesters, administrators and researchers. There is no GUI. It is in the first version and may contain some bugs.*

# Compiling
In order to compile and use TLS-Scanner, you need to run:
 
```bash
$ cd TLS-Scanner
$ git submodule update --init --recursive
$ mvn clean package

```
Alternatively, if you are in a hurry, you can skip the tests by using:
```bash
$ mvn clean package -DskipTests=true
```

If you want to use TLS-Scanner as a library you need to install it with the following command:
```bash
$ mvn clean install
```

# Running
In order to run TLS-Scanner you need to run the jar file in the apps/ folder.

```bash
$ java -jar apps/TLS-Server-Scanner.jar -connect localhost:4433
```

You can specify a host you want to scan with the -connect parameter. If you want to improve the performance of the scan you can use the -threads parameter (default=1).


# Docker
We provide you with a Dockerfile, which lets you run the scanner directly:

```bash
$ docker build . -t tlsscanner
$ docker run -t tlsscanner
```

**Please note:**  *I am by no means familiar with Docker best practices. If you know how to improve the Dockerfile
 feel free to issue a pull request*

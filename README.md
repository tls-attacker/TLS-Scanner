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

In order to see more details about the Guidelines, use "-reportDetail ALL".

# Docker

We provide you with a Dockerfile, which lets you run the scanner directly:

```bash
$ docker build . -t tlsscanner
$ docker run -t tlsscanner
```

**Please note:**  *I am by no means familiar with Docker best practices. If you know how to improve the Dockerfile
feel free to issue a pull request*


# Requirement System

(TLS) probes sometimes have prerequisites which are required to execute this specific probe. The requirement system allows to define sets of such requirements which must be fulfilled to execute a probe.

Requirements can be concatenated by several ways. You can use a logical *not* by including a requirement in the `NotRequirement`, a logical *or* by putting the respective requirement objects in an `OrRequirement`, and a logical *and* by applying the require function on a requirement object by using the builder pattern of the requirement class. 
The different types of `Requirement`s can be the execution of one or multiple probes (`ProbeRequirement`), fulfilled (`PropertyRequirement`) or not fulfilled properties (`PropertyNotRequirement`), supported extension types (`ExtensionRequirement`), supported protocol versions (`ProtocolRequirement`), a working configuration (`WorkingConfigRequirement`), or optional flags (`OptionsRequirement`).

If nothing is required, you can use the static Requirement.NO_REQUIREMENT which always evaluates to true.

Examples like the following can be found in the `probe` packages of the `tls-client-` and `tls-server-scanner`.

```code
    @Override
    protected Requirement getRequirements() {
        return new ProbeRequirement(TlsProbeType.EXTENSIONS)
                .requires(new ExtensionRequirement(ExtensionType.ALPN));
    }
```
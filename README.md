# TLS-Scanner

![GitHub release (latest by date)](https://img.shields.io/github/v/release/tls-attacker/TLS-Scanner)
![licence](https://img.shields.io/badge/License-Apachev2-brightgreen.svg)
[![Build Status](https://hydrogen.cloud.nds.rub.de/buildStatus/icon.svg?job=TLS-Scanner)](https://hydrogen.cloud.nds.rub.de/job/TLS-Scanner/)

TLS-Scanner is a tool to assist pentesters and security researchers in the evaluation of TLS server and client configurations.

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

In order to run TLS-Scanner you need to run one of the jar files in the apps/ folder.
These can be obtained by compiling the app yourself or by
[downloading released jar files from GitHub](https://github.com/tls-attacker/TLS-Scanner/releases).

```bash
$ java -jar apps/TLS-Server-Scanner.jar -connect localhost:4433
```

You can specify a host you want to scan with the -connect parameter. If you want to improve the performance of the scan you can use the -threads parameter (default=1).

In order to see more details about the Guidelines, use "-reportDetail ALL".

# Docker

We provide prebuilt docker images for easy use of the TLS-Server-Scanner.

```bash
$ docker run -it --network host ghcr.io/tls-attacker/tlsscanner -connect localhost:4433
```

The image is made to be used for server-scanning but also contains the other jar files.
They can be accessed by altering the entrypoint.

```bash
$ docker run -it --network host --entrypoint java ghcr.io/tls-attacker/tlsscanner -jar TLS-Client-Scanner.jar
```

We also provide you with a Dockerfile, to build the container yourself:

```bash
$ docker build . -t tlsscanner
$ docker run -t tlsscanner
```

**Please note:**  *I am by no means familiar with Docker best practices. If you know how to improve the Dockerfile
feel free to issue a pull request*

# Requirement System

(TLS) probes sometimes have prerequisites that are required to execute this specific probe. The requirement system allows you to define sets of such requirements that must be met in order for the probe to be executed.

Each requirement offers an `evaluate` function which returns a boolean value indicating whether the requirement has been fulfilled.
Requirements can be concatenated in several ways using well-known logical operations. Each requirement offers `and`, `or`, `not`, and `xor`
instance methods to chain multiple requirements. The following probes are currently implemented and can be used off the shelf:

- `FulfilledRequirement` - Always evalutes to `true`, useful to indicate no requirement.
- `UnfulfillableRequirement` - Always evalutes to `false`, prevents execution of probes.
- `ProbeRequirement` - Evaluates to `true` if the specified probe(s) has been executed.
- `PropertyRequirement` - Evaluates to `true` if the specified analyzed properties have a predefined value. The value may either be provided as a constructor parameter or one may use `PropertyTrueRequirement` and `PropertyFalseRequirement` as a shorthand for `TestResults.TRUE` and `TestResults.FALSE`.
- `PropertyComparatorRequirement` - Evaluates to `true` if the collection result of an analyzed property is smaller, equal, or greater than a constant value.
- `ProtocolRequirement` - Evaluates to `true` if certain protocol versions are supported.
- `ExtensionRequirement` - Evaluates to `true` if certain extensions are supported by the remote peer.
- `OptionsRequirement` - Evaluates to `true` if additional cli flags are set. Currently used in some client probes (ALPN, SNI, session resumption).
- `WorkingConfigRequirement` - Evaluates to `true` if a working configuration has been found.

Aside from these predefined requirements one may also extend the `Requirement` class anonymously within the `getRequirements` method. If nothing is required, you can use may return a `FulfilledRequirement` which always evaluates to true.

Examples on how to use requirements can be found in the `probe` packages of the `tls-client-scanner` and `tls-server-scanner`.

```java
@Override
public Requirement<ClientReport> getRequirements() {
    return new ProbeRequirement<ClientReport>(TlsProbeType.CIPHER_SUITE)
            .and(new PropertyTrueRequirement<>(TlsAnalyzedProperty.SUPPORTS_DHE));
}
```


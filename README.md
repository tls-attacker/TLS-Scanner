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

## Important Parameters

You must specify a host you want to scan with the -connect parameter.

If you want to improve the performance of the scan, you can use the `-threads` parameter to increase the number of used threads.

Another important parameter for performance reasons is the `-scanDetail` parameter, which can be used to configure how detailed you want to scan. Possible values ranging from fast to very detailed are: QUICK, NORMAL, DETAILED, ALL.

The detail of the output can be configured with the `-reportDetail` parameter. In order to see more details about the Guidelines, use `-reportDetail ALL`.

By default, the results are written to the console only. If you want to have machine-readable output, you can use `-outputFile output.json` to automatically write the results in a JSON file.

## Use Cases

The most important parameters to change are `-scanDetail` and `-reportDetail`. In the following, we explain some use cases for these parameters.

### Default Scan

For most cases, our default parameter settings are sufficient. This performs a scan with both detail levels set to `NORMAL`.

### Fast Scan

If you want to perform a fast scan and get a quick overview over your system, we recommend to use both detail levels set to `QUICK`. This limits the extend of some executed probes to lower the runtime and limits the report detail to not include very detailed and technical information.

### Detailed Scan

If you want to fully evaluate your system and execute everything that we have, we recommend to use both detail levels set to `ALL`. This executes all existing probes fully and prints very detailed information for further analysis and evaluation.

## All Parameters

The following information can also be obtained by using the -help parameter or executing the jar without any parameters at all:

```
-additionalRandomCollection
Number of connections that should be additionally performed to collect more randomness data to get more accurate analysis
Default: 0

-afterExecutionCb
The shell command the scanner should run after the worklfow execution.

-afterTransportInitCb
The shell command the scanner should run after the initialization of the transport handler.

-applicationProtocol
Which application data protocol the server is running.
Default: HTTP
Possible Values: [ECHO, STUN, TURN, VPN_CITRIX, VPN_FORTINET, COAP, HTTP, FTP, SMTP, IMAP, LDAP, UNKNOWN, OTHER]

-beforeTransportInitCb
The shell command the scanner should run before the initialization of the transport handler.

-beforeTransportPreInitCb
The shell command the scanner should run before the pre initialization of the transport handler.

-ca
Add one or more custom CA's by separating them with a comma to verify the corresponding chain of certificates.

-client_authentication
Enables client authentication during TLS handshakes

-config
This parameter allows you to specify a default TlsConfig

-configSearchCooldown
Pause between config tests to ensure the server finished processing the previously rejected messages.
Default: false

-connect (required)
Who to connect to. Syntax: localhost:4433

-controlProxy
Required by DtlsIpAddressInCookie probe. Syntax: 127.0.0.1:5555

-dataProxy
Required by DtlsIpAddressInCookie probe. Syntax: 127.0.0.1:4444

-debug
Show extra debug output (sets logLevel to DEBUG)
Default: false

-doNotSendSNIExtension
Usually the hostname for the SNI extension is inferred automatically. This option can overwrite the default behaviour.
Default: false

-dtls
Scan DTLS
Default: false

-exclude
A list of probes that should be excluded from the scan. The list is separated by commas.
Default: []

-h, -help
Prints usage for all the existing commands.

-keylogfile
Path to the keylogfile

-noColor
If you use Windows or don't want colored text.
Default: false

-outputFile
Specify a file to write the site report in JSON to

-parallelProbes
Defines the number of threads responsible for different probes. If set to 1, only one specific probe can be run in time.
Default: 1

-postAnalysisDetail
How detailed do you want the post analysis to be
Default: NORMAL
Possible Values: [ALL, DETAILED, NORMAL, QUICK]

-probeTimeout
The timeout for each probe in ms (default 1800000)
Default: 1800000

-quic
Scan the QUIC protocol.

Default: false
-quiet
No output (sets logLevel to NONE)
Default: false

-reportDetail
How detailed do you want the report to be?
Default: NORMAL
Possible Values: [ALL, DETAILED, NORMAL, QUICK]

-scanDetail
How detailed do you want to scan?
Default: NORMAL
Possible Values: [ALL, DETAILED, NORMAL, QUICK]

-server_name
Server name for the SNI extension.

-starttls
Which STARTTLS type to use.
Default: NONE
Possible Values: [NONE, FTP, IMAP, POP3, SMTP]

-threads
The maximum number of threads used to execute probes located in the queue.
Default: 1

-timeout
The timeout used for the scans in ms.
Default: 1000
```

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


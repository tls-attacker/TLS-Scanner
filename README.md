# TLS-Scanner
TLS-Scanner is a Tool created by the Chair for Network and Data Security from the Ruhr-University Bochum to assist pentesters and security researchers in lthe evaluation of TLS Server configurations. 

**Please note:**  *TLS-Scanner is a research tool intended for TLS developers, pentesters, administrators and researchers. There is no GUI. It is in the first version and may contain some bugs.*

# Compiling
In order to compile and use TLS-Scanner, you need to have Java installed, as well as TLS-Attacker and the ModifiableVariable package.
```bash
$ cd TLS-Scanner
$ ./mvnw clean package

```
Alternatively, if you are in hurry, you can skip the tests by using:
```bash
$ ./mvnw clean package -DskipTests=true
```

If you want to use TLS-Scanner as a library you need to install it with the following command:
```bash
$ ./mvnw clean install
```

For hints on installing the required libraries checkout the corresponding GitHub repositories:

[TLS-Attacker](https://github.com/RUB-NDS/TLS-Attacker-Development)

[ModifiableVariables](https://github.com/RUB-NDS/ModifiableVariable)

# Running
In order to run TLS-Scanner you need to run the jar file in the apps/ folder.

```bash
$ java -jar apps/TLS-Scanner.jar -connect localhost:4433
```

You can specify a host you want to scan with the -connect parameter. If you want to improve the performance of the scan you can use the -threads parameter (default=1).


# Results
TLS-Scanner uses the concept of "Checks" which are performed after it collected configuration information. A check which results in "true" is consideres a non optimal choice and is an indicator for a pentester for a possible problem.

There are currently multiple checks implemented:


| Check                           | Meaning                                                                  | 
| ------------------------------- |:------------------------------------------------------------------------:|
| CERTIFICATE_EXPIRED             | Checks if the Certificate is expired yet                                 |
| CERTIFICATE_NOT_VALID_YET       | Checks if the Certificate is valid yet                                   |
| CERTIFICATE_WEAK_HASH_FUNCTION  | Checks if the Server uses a weak Hash algorithm for its Certificate      |
| CERTIFICATE_WEAK_SIGN_ALGORITHM | Checks if the Server uses a weak Signature algorithm for its Certificate |
| CERTIFICATE_NOT_SENT_BY_SERVER  | Checks if the Server did sent a Certificate at all                       |
| CIPHERSUITE_ANON                | Checks if the Server has Anon Ciphersuites enabled                       |
| CIPHERSUITE_CBC                 | Checks if the Server has CBC Ciphersuites enabled for TLS 1.0            | 
| CIPHERSUITE_EXPORT              | Checks if the Server has Export Ciphersuites enabled                     |
| CIPHERSUITE_NULL                | Checks if the Server has Null Ciphersuites enabled                       |
| CIPHERSUITE_RC4                 | Checks if the Server has RC4 Ciphersuites enabled                        |
| CIPHERSUITEORDER_ENFORCED       | Checks if the Server does not enforce a Ciphersuite ordering             |
| PROTOCOLVERSION_SSL2            | Checks if SSL 2 is enabled                                               |
| PROTOCOLVERSION_SSL3            | Checks if SSL 3 is enabled                                               |

**Please note:**  *A Check with a _result_ of true is considered non optimal*

# TLS-Crawler

The TLS-Crawler is designed to perform large scale scans with the TLS-Server-Scanner from this repository.
To improve performance it supports distributing the workload to multiple machines.

## Architecture

![](docs/img/tls-crawler-architecture.drawio.svg)

The TLS-Crawler is split into two applications:
- the Controller which is responsible for creating scan jobs, distributing them among multiple workers and scheduling recurring scans
- the Worker which is responsible for performing the scans

Additionally, for distributing the work and persisting results two more components are required:
- a RabbitMq instance which handles the work distribution among workers
- a MongoDB database instance which stores the results of the scans.

## Getting Started

### Building

The TLS-Crawler is a module of the TLS-Scanner Maven project. Build it from the repository root:

        mvn clean install

To build only the TLS-Crawler and the modules it depends on, use `mvn clean install -pl TLS-Crawler -am`.
The runnable `TLS-Crawler.jar` is placed in the `apps/` folder of the repository root, its dependencies in `apps/lib/`.

### Examples

Controller

        java -jar apps/TLS-Crawler.jar controller -tranco 1000 -denylist resources/denylist.txt -portToBeScanned 443 -mongoDbHost mongo -mongoDbPort 27017 -mongoDbUser mongoadmin -mongoDbPass mongoadminpw -mongoDbAuthSource admin -rabbitMqHost rabbitmq -rabbitMqPort 5672 -scanName scanResults -monitorScan -parallelProbes 1 

Worker

        java -jar apps/TLS-Crawler.jar worker -mongoDbHost mongo -mongoDbPort 27017 -mongoDbUser mongoadmin -mongoDbPass mongoadminpw -mongoDbAuthSource admin -rabbitMqHost rabbitmq -rabbitMqPort 5672  -numberOfThreads 30 -parallelProbeThreads 50

## Controller Commandline Reference

Scanner specific Configuration:
- `-portToBeScanned` the port that should be scanned
- `-timeout` the timeout to use inside the TLS-Scanner
- `-reexecutions` the number of reexecutions to use in the TLS-Scanner
- `-parallelProbes` number of TLS-Scanner probes that may run in parallel per scan target (default: 1) WARNING: For large scale scans, this should be kept at 1 to avoid excessive resource consumption and potential instability.
- `-starttls` which start tls protocol should be used (required when scanning email servers)
- `-scanDetail` detail for the scanner (ALL, DETAILED, NORMAL, QUICK)

General Configuration:
- `-scanName string` the name of the scan
- `-hostFile path` a file with the list of servers which should be scanned, see [HostFile](#hostfile)
- `-denylist path` a file with hosts/ip addresses or ip ranges that should not be scanned
- `-notifyUrl` url to which an HTTP POST request should be sent when a bulk scan is finished
- `-monitorScan` if set the controller monitors the progress of the scan and logs periodically how many servers have been scanned
- `-tranco int(=X)` if set the controller downloads the most recent [Tranco List](https://tranco-list.eu/) and scans the top X hosts

## Worker Commandline Reference

- `-numberOfThreads` number of worker threads the crawler worker should use
- `-parallelProbeThreads` number of threads used for parallel connections, shared between all worker threads
- `-scanTimeout` timeout after which the crawler tries to stop a scan if its still running (should be lower than rabbitMQ consumer ack because messages are only acknowledged at the end of a scan or the timeout)

## MongoDB Commandline Configuration

These options apply to both the controller and the worker.

- `-mongoDbHost` host of the MongoDB instance the crawler should save the results in
- `-mongoDbPort` port of the MongoDB instance the crawler should save the results in
- `-mongoDbUser` username to be used to authenticate with MongoDB
- `-mongoDbPass` password to be used to authenticate with MongoDB
- `-mongoDbPassFile` path to file from where the password should be read (for use with docker secrets)
- `-mongoDbAuthSource` the DB within the MongoDB instance, in which the user:pass is defined

## RabbitMQ Commandline Configuration

These options apply to both the controller and the worker.

- `-rabbitMqHost` hostname or ip of the RabbitMQ instance
- `-rabbitMqPort` port of the RabbitMQ instance
- `-rabbitMqUser` username to be used to authenticate with RabbitMQ
- `-rabbitMqPass` password to be used to authenticate with RabbitMQ
- `-rabbitMqPassFile` path to file from where the password should be read (for use with docker secrets)
- `-rabbitMqTLS` if the connection to the RabbitMQ instance should be TLS encrypted

## HostFile

The hosts to be scanned can be specified as domain or ip with or without port. Each line must only contain one host.
If no port is specified the port passed with the `-portToBeScanned` parameter is used (defaults to 443).

Example:

```
www.google.com:443
amazon.de
131.234.238.217:8080
131.234.238.217
```

## Using Docker Compose

Instead of building the crawler yourself and starting it from the commandline, you can use `docker-compose.yml` and
`build-docker-image.sh` in this folder. The images are built from `Dockerfile.Crawler` in the repository root, which
builds the TLS-Crawler together with the TLS-Scanner modules from the current state of the repository.
All parameters for the scan can be defined in the `docker-compose.yml`. `build-docker-image.sh` can be used to build the
crawler using specifiable branches of the dependencies `TLS-Attacker`, `Crawler-Core` etc. (set a branch to `N/A` to use
the released version from Maven instead). If you build any dependency from a branch, set your GitHub access token in
`build-docker-image.sh` so Docker can download it. Finally, running `./build-docker-image.sh` will build your custom
crawler environment in Docker images. Using `docker compose up` you can then start the scan. You can either use the
MongoDB specified in the `docker-compose.yml` or use an external database.

# TLS-Crawler
TLS-Crawler is being developed as part of the bachelor thesis "Mapping the current TLS landscape using TLS Attacker".
The software will be able to scan the IPv4 range, identify hosts offering TLS connections and analyzing their capabilities using TLS-Attacker.
The goal is to continuously scan and gather data on TLS adoption and possibly the pervasion of detectable weaknesses.

### Design Considerations
Requirements, an MVP and the preliminary architecture.

#### Minimum Viable Product
The minimum viable product or MVP is the most simple piece of software that would fulfill all MUST requirements.
For this project, an MVP would have to be able to do the following:

- Schedule Scans (i. e. generate target IPs)
- Perform Scans
- Persist Scan Results

Additionally, it should be able to do this in an efficient manner.
To this point no "hard" performance goal has been defined.
A "soft" performance goal is to be able to scan the IPv4-space on roughly a weekly basis.
It is safe to assume that a naive implementation (Generate IP, Scan, Persist, Repeat) will miss this performance goal by far.

#### Additional Requirements
The MVP as pictured above leaves a few things to be desired.
These points all pose notable improvements over the MVP and are to be addressed for the first major release, if time permits:

- Concert scans among multiple machines so to achieve a high maximum performance
- Generate statistics based on the data from previous scans
- Providing an interface to interactively display data

#### Performance Considerations
Apart from multithreading being virtually set in stone to improve performance, these technologies could also help:
- Non-Blocking IO: Most of the time, scans will be waiting for responses.
NBIO improves performance by not blocking execution while waiting.
- Two-Step Scanning: Most of the time, hosts will just not reply when contacted.
This problem has been solved with other crawlers. Using a two-step scan to identify scannable hosts first and starting a full scan then would probably highly increase performance.

#### Architecture

The architecture is not yet decided upon.
This is mainly due to an outstanding decision whether to implement multithreading with a threadpool and synchronized message queues, or using ReactiveX to handle the data pipeline-style.

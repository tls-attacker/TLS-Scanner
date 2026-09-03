# Scan Profiles

Example scan profiles for the `-profile <path/to/profile.json>` parameter provided by
[Scanner-Core](https://github.com/tls-attacker/Scanner-Core)'s `ExecutorConfig`. It is available
on both `TlsServerScanner` and `TlsClientScanner` (via `ServerScannerConfig`/`ClientScannerConfig`
-> `TlsScannerConfig` -> `ExecutorConfig`), replacing the old `-exclude` parameter.

A profile is a JSON file with:

- `name`: the profile's name, used by other profiles to inherit from it.
- `inheritedFromProfiles`: names of other profiles to combine probes from. Referenced profiles are
  looked up among the other `*.json` files in the same directory as the profile you point
  `-profile` at.
- `probes`: the probes to run, each identified by the fully qualified name of the `ProbeType` enum
  class implementing it plus the constant name. A single profile can freely mix probes from
  different `ProbeType` implementations, e.g. `TlsProbeType` and `QuicProbeType`.

Only the probes resolved from the active profile (and everything it inherits from) are executed;
everything else is skipped.

## Usage

```bash
java -jar TLS-Server-Scanner.jar -connect example.com:443 -profile scan-profiles/tls-and-quic.json
```

## Files here

- [`quick-tls.json`](quick-tls.json) — a handful of cheap, high-signal TLS probes.
- [`tls-and-quic.json`](tls-and-quic.json) — inherits `quick-tls` and adds a couple of QUIC probes,
  demonstrating that a profile can combine probes from multiple `ProbeType` implementations.


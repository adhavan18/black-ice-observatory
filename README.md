# black ice observatory

black ice observatory is a defensive security intelligence workbench for malware analysis, adversary tracking, threat landscape reporting, and incident response.

it is designed around one rule: suspicious files are never executed. the platform works with hashes, safe metadata, extracted strings, analyst notes, and synthetic endpoint telemetry. it produces explainable findings that a security team can review before taking action.

## the idea

security teams receive messy reports from many places. one report may contain a hash, another may describe a process tree, and a third may mention a campaign name. this project normalizes those reports into one case graph:

```text
internal report + external report + endpoint telemetry
                         |
                         v
                    normalize
                         |
                         v
       indicators + behaviors + intelligence requirements
                         |
                         v
     signatures + behavioral profile + confidence score
                         |
                         v
       incident actions + security review + threat report
```

## capabilities

- static malware analysis with sha256, file metadata, strings, and safe feature extraction
- pe and elf magic/header inspection plus entropy analysis without execution
- vulnerability prioritization using cvss, internet exposure, and known-exploitation signals
- signature detection using a small transparent rule engine
- scored detection rules using regular expressions plus required behavioral features
- behavioral profiling as a named ml technique using explainable feature weights
- adversary tracking with aliases, campaigns, techniques, and confidence levels
- threat intelligence processing for internal and external reports
- threat landscape summaries by sector, technique, region, and time
- intelligence requirements that turn unknowns into collection tasks
- incident response actions with containment, evidence, eradication, and recovery steps
- first-party mitigation recommendations for the affected service owner
- operational security checks for secrets, unsafe logging, and over-broad access
- security defect and vulnerability identification with severity and ownership
- security review reports that identify gaps in security guidance
- partitioned ingestion benchmark with queueing, backpressure, and throughput metrics
- a real bounded worker queue for batch report ingestion
- partitioned load testing with throughput metrics and bounded backpressure
- an opsec scanner for fake secrets and unsafe logging patterns

## important safety boundary

this repository does not execute malware, create payloads, bypass detection, exploit systems, steal credentials, or provide persistence and evasion instructions. samples are represented by safe metadata and synthetic telemetry only. production deployments should isolate real samples in a separately approved detonation environment with legal, privacy, and safety controls.

## quick start

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -e .
python -m black_ice.cli analyze examples/report.json
python -m black_ice.cli landscape examples/landscape.json
python -m black_ice.cli vulnerabilities examples/vulnerabilities.json
python -m black_ice.cli opsec .
python -m black_ice.cli ingest examples/landscape.json
python -m black_ice.cli load-test examples/landscape.json
python -m black_ice.cli disassemble examples/benign_x86.bin
pytest
```

## example output

```text
case: case-2026-001
verdict: high confidence suspicious
signature hits: macro_dropper, encoded_command
behavior profile: collection=0.10 execution=0.90 persistence=0.35
tracked actor: aurora-lynx
priority actions: isolate host, preserve evidence, rotate exposed tokens
```

## project map

```text
src/black_ice/
  analysis.py       safe static analysis, pe/elf headers, entropy, indicators
  behavior.py       explainable behavioral profiling
  intelligence.py   report normalization and adversary tracking
  response.py       incident response and mitigation plans
  review.py         security defects and guidance gaps
  scale.py          ingestion scaling design checks
  pipeline.py       bounded worker queue for report ingestion
  vulnerability.py  cvss and exposure prioritization
  opsec.py          secret and unsafe logging checks
  cli.py            command line interface
examples/           safe synthetic reports
tests/              unit tests for every core capability
.github/            ci and security checks
```

## how i would extend it

- connect s3 or object storage to the ingestion queue
- add kafka or kinesis partitions by tenant and report type
- store indicators in opensearch and relationships in a graph database
- add an approved sandbox connector behind a separate service boundary
- add signed analyst approvals before blocking a domain or isolating a host
- send detections to a siem, edr, ticketing system, and case-management api

## safe reversing and local security testing

`docs/reverse-engineering.md` explains the non-executing pe/elf fixture workflow. `docs/authorized-testing.md` defines the local-only security test boundary. no external target is attacked by this repository.

the repository includes a tiny localhost-only target in `labs/authorized_target.py` and a test that starts it, checks its health contract, and terminates it. this is a local security-test harness, not a penetration test. any real penetration test needs written authorization and a separate scope.


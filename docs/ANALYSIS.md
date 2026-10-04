# Application analysis

`crepe analyze FILE [--format json|table|csv]` feeds link-decoded packets
through bounded IP fragment and directional TCP reconstruction.

DNS UDP/TCP, cleartext TLS ClientHello/ServerHello metadata, initial HTTP/1.x
headers and SSH banners are implemented. Packet capture timestamps control
stream/fragment expiry; wall-clock time controls live commands. EOF, gap,
overlap, timeout, reset and resource exhaustion remain observable.

See [OPERATIONS.md](OPERATIONS.md) for exact limits and protocol limitations,
[SCHEMA.md](SCHEMA.md) for event shapes, and `crates/crepe-analysis/tests` for
reorder, duplicate, midstream, malformed, incomplete and mutation tests.
`fixtures/protocols.pcap` and `fixtures/fragments.pcap` are generated entirely
from synthetic data. `scripts/smoke-platform.py` verifies actual local TCP
connections in addition to these deterministic fixtures.

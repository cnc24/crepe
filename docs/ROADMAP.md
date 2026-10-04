> Private prototype planning record, not a published release or license grant.
> Current publication acceptance is defined in RELEASE-1.1.md.

> Scope correction: this document records the earlier, narrower release plan.
> See [original-design status](DESIGN-STATUS.md) for the unmet full-design 1.0 gates.

# Release scope

The full 1.0 acceptance gate is tracked in [RELEASE-1.0.md](RELEASE-1.0.md).
This expands the original packet prototype through bounded reassembly and
protocol metadata, flow export collection, durable history and local queries.

Later versions can add full HTTP transaction/body framing, TLS certificate
and richer handshake records, QUIC, globally correlated connection epochs,
CIDR predicates in historical CQL, vendor IPFIX elements, template persistence,
periodically committed collector windows, retention/compaction, and richer
observational rules. These extend the documented 1.0 contracts.

AF_XDP, distributed clustering, external plugins, a web UI and active blocking
remain outside the 1.0 target. Performance figures must identify workload,
hardware and build; no 100-Gbit throughput claim is made.

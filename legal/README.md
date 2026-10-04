# Third-party redistribution

The current development tree uses the Crepe Source Available License 1.0
(see ../LICENSE and ../docs/LICENSING.md). Crepe's license does not replace
third-party licenses.
`THIRD-PARTY-NOTICES.txt` preserves the dependency notices, copyright statements
and license files, including nested native-source licenses and Apache NOTICEs.
`inventory.json` records package versions, declared license expressions and
SHA-256 hashes of the evidence. The inventory intentionally includes optional,
build and cross-platform packages, even when absent from a particular binary.

Regenerate after dependency changes with `python3 scripts/licenses.py`.
Review new expressions and any missing upstream evidence. `--check` and release
packaging fail on stale notices, missing declarations or missing evidence.
The generator fetches Cargo packages as necessary, but never fetches supplemental
legal files. `upstream/` contains checked-in supplements for crates whose
published archives omit licenses; provenance records pin downloaded texts to
upstream commits. For packages declaring MIT but supplying no standalone text,
the declared authors/README are retained and the standard MIT text is provided.
These are transparent metadata-based supplements, not new license grants.

For OR expressions Crepe selects a permissive option (MIT, Apache, BSD, etc.),
not the optional LGPL path of r-efi. AND expressions remain cumulative.
Including an alternative upstream license text does not mean Crepe selects it.
System libraries, including libpcap and macOS frameworks, are dynamically linked
and are not copied into release archives. Their separate OS/distribution terms
continue to apply. objc2's own notes concerning Apple SDK-derived bindings are
preserved in the notices; this inventory is not a legal opinion on those terms.

Release archives additionally carry Rust standard-library copyright/license
materials from the packaging toolchain, with that toolchain's identity. A
license-only repair preserves original executable bytes; it is not a rebuild.
Upstream metadata/evidence cannot prove the provenance of every line of code.

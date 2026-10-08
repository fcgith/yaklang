# Versioned traffic corpus

Capture-backed tests read password ZIP batches through
[`internal/trafficfixture`](../../../../internal/trafficfixture). Password:
`bin-parser`. This is a packaging convention, not protection for credentials.
No additional ZIP library, download or extraction step is needed for Go tests.

`index.json` pins each ZIP SHA256, every member's SHA256 and expanded size,
and historical path aliases. Indexed inputs always come from the ZIP; a loose
copy cannot shadow them. All reads return owned bytes. Filename-only APIs use
verified copies in test-owned temporary directories, removed by `t.Cleanup`.

The baseline seals 694 captures (690 unique content hashes) and their original
answers from `2fb090d177c3bf52277f240b2dca05ea80216485`. The source ZIP SHA256 is
`2ac6c0e1861b3d9487230fd8d89106780c2f856e67c2873fe99c270d0b92b234`.
The repository batch preserves every capture byte and original path. Five
existing fixture keylogs remain separate; they are excluded from this ZIP.
The auxiliary batch preserves remaining binary inputs, manifests and endpoint
evidence. Provenance, fixed upstream commits, licenses and evidence categories
remain inside these archives. Artificial and upstream fixtures do not become
claims of real capture merely because they are archived.

The sealed answer inventory has 622 partially mapped and 72 unmapped cases.
Its executable assertions include 434 selected-input parses, 102 selected-input
rejections and 30 exact whole-capture protocol/status count maps. A selected
frame's assertions are not a golden for every message in the capture.
`TestFrozenCorpusSelectedInputs` consumes the sealed field/error assertions;
`TestFrozenCorpusReplay` executes every capture, checks full/deferred fields,
errors, associations, stream offsets and resource release, and compares sealed
event counts where available. Replay parity alone is not independent semantics.
The existing endpoint, field, negative and worker/callback/chunk regression
tests keep their stronger assertions while reading the same archived inputs.

Run from the repository root:

```sh
go test -json -count=1 -timeout=5m ./internal/trafficfixture ./common/bin-parser/... ./common/pcapx/... ./common/yak/cmd/yakcmds/shark-cli > traffic.jsonl
python3 scripts/protocol-tests/check_go_test_json.py traffic.jsonl --inventory scripts/protocol-tests/required-tests.json --tier full
```

Add future captures and answers as a **new** batch. Do not rewrite old ZIPs,
replace old aliases, regenerate answers from the implementation under test,
or turn an unmapped oracle into a passing semantic result. Preserve fixed
source/version, content hash, format, packet counts, license, evidence category,
independent expected fields/errors and their validation scope. Deduplicate by
content hash and preserve distinct path aliases. Keep new batches below 25 MiB
compressed and each member below 25 MiB expanded; the loader also caps expanded
batch size and rejects unsupported encryption, traversal and duplicate members.
New answer-bearing batches use `validation/expected.json` schema 1 and enter the
frozen gates automatically. Add adapters for new assertion kinds before claiming
their semantic coverage. Keys, credentials and material without redistribution
permission belong in an external fixed-source download manifest.

Current test requirements live in `scripts/protocol-tests/required-tests.json`;
the baseline's historical requirements remain sealed with its evidence. Test
logs, profiles and iteration reports belong outside the repository.

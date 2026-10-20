# Licensebox application SDK

Read the shared [SDK instructions](https://github.com/licensebox/protocol/blob/main/AGENTS.md)
and [maintenance process](https://github.com/licensebox/protocol/blob/main/MAINTAINING.md)
before changing client behavior. The exact tested contract is protocol-lock.json.

Add or update the shared regression scenario first, then port every affected SDK.
Run the full shared suite and applicable native, race, memory and install checks.
Update the contract revision and release compatibility map. A failing client
blocks release; do not weaken checks to make a port pass. The scheduled sync
opens tested pin/dependency PRs; implementation ports still require review.

Administration stays in the Go CLI. Linux is the initial validated platform.
Never copy private consuming-application source, documentation, references,
production keys, tokens or customer records into this public SDK repository.
Tests use synthetic keys and records only. Preserve maintained hybrid Ed25519 + ML-DSA-65 crypto,
native machine binding and fail-closed explicit policy refusals.

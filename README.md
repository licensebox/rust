# Licensebox for Rust

Application licensing backed by the shared C core: native machine identity,
email sign-in, signed offline leases, silent renewal, module access, approval
requests and usage reporting. Linux is the initial runtime target.

Requirements: Rust 1.74+ and serde_json; Licensebox C >=0.2.0, OpenSSL 3, libcurl 7.85+ and
json-c. The native dependency is pinned in `native-version.txt` and updated by
the tested contract-sync workflow. No native code is downloaded at runtime.

## Install the native dependency

Clone this repository/tag. Install native development packages, then run:

```sh
sudo apt install build-essential cmake git libssl-dev libcurl4-openssl-dev libjson-c-dev
bash scripts/install-native.sh "$PWD/.native"
export LICENSEBOX_LIB_DIR="$PWD/.native/lib"
export LICENSEBOX_LIBRARY="$PWD/.native/lib/liblicensebox.so"
export LD_LIBRARY_PATH="$PWD/.native/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
```

Use that absolute native library directory when running the consuming app.
It may instead be installed in the system loader's normal search path.
The helper builds the pinned public C release without changing system folders.

## Authorize protected work

```rust
use licensebox::{Client, Config};
use std::collections::BTreeMap;
let mut options = Config::new("myapp", BTreeMap::from([
    ("myapp-k1".into(), "YOUR_PUBLIC_VERIFICATION_KEY".into())
]));
options.version = "1.0".into();
let mut client = Client::new(options)?;
client.require("export")?;
// Protected work starts here.
```

Add the crate from this GitHub repository/tag; registry publication is separate.
`Error.code` is stable. Results are owned `serde_json::Value` values. Client calls
require mutable access; clients are deliberately not Send/Sync. `Drop` destroys
the native handle. Callback allocations stay valid when a client moves.


Create one client per process. The complete API includes lease, require, local
status, explicit sign-in, logout, module discovery, access requests/listing,
private access links, and fixed command usage records. Rust/Julia use snake_case;
Java uses lowerCamelCase; .NET uses PascalCase. See source API signatures and the
conformance adapter for examples of every operation. Get product/module IDs and
**public verification keys** from the administrator. Never embed admin tokens,
private signing keys or copied installation keys.

Sign-in defaults to instructions on stderr; a callback can present them in your
UI. Cancellation is supported. Callback failures stop the operation and never
unwind into native code. Callbacks must not reenter the client. Clock/native
binding providers are trusted platform/testing seams, never end-user identity
overrides. Config strings and keys are copied by the native client.

## Errors and lifecycle

`machine_changed`, `seat_transferred`, `location_denied` and `location_unknown`
refuse protected work and persist across restart/offline use. Explicit sign-in
can transfer a seat; ordinary renewal cannot take one back. `module_denied`
means missing module access; `offline` means an expired lease could not renew;
`revoked` removes cached access. Always stop protected work on an error.

Each process silently renews on first protected use, bounded to three seconds.
A verified, unexpired cached lease permits offline use during transport/server
outages. Default allowance is 24 hours; there is no background heartbeat. Logout
retains installation identity. Native IDs stay local; only a product-scoped
digest is sent. Cloned/spoofed IDs and modified host software remain limitations:
this is not hardware attestation. Payments and billing are handled separately
by product administrators.

Other operating systems and browser/WASM are not supported by this native C
profile yet. Test/validation status is recorded in GitHub Actions; do not infer
platform support merely because a language runtime exists there.

See [shared protocol and tests](https://github.com/licensebox/protocol),
[the full roadmap](https://github.com/licensebox/protocol/blob/main/ROADMAP.md)
and [integration docs](https://licensebox.dev/docs). Administration remains in
the [Go CLI](https://github.com/licensebox/go) and web console.

MIT. Copyright © 2026 [Vijai Kumar](https://meshing.engineer).

## Optional protected-work checkpoints

```rust
let checkpoint = client.heartbeat("core")?;
// An error returns before the next protected unit.
```

The result is the owned JSON value/string `{"lease":{...},"online":true|false}`
using this binding's existing JSON and cleanup conventions.

The explicit checkpoint always attempts signed renewal with a three-second
network bound, even after a cached `Require` succeeded. It never activates,
opens interactive sign-in, creates/rotates an installation key or transfers a
seat. Missing saved state returns `not_signed_in`; invalid saved state, a removed
module or explicit server refusal fails closed. Eligible outages may return a
verified unexpired saved lease with `online=false`, without extending its signed
expiry or clearing a saved refusal. A successful renewal replaces cached grants
before checking the requested nonempty module.

Use the matching native core containing the heartbeat API. Consumers own their
event loop and safe stop/pause behavior. Read the optional verified `heartbeat`
policy (`interval_seconds`, `grace_seconds`) to schedule checks; missing/null is
legacy policy. Independently stop protected work by the last verified `expires`
even when renewal is slow, and never move that deadline after a failed check.
Construction, Lease and Require start no background worker. Callback lifetime,
thread ownership and reentry requirements remain unchanged; the SDK never kills
the application or discards application results.

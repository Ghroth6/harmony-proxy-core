# Mobile validation export

This backend owns `mobile/validation` and the versioned byte-buffer C export in
`cmd/mobile`. The application operation and receipt contract are authoritative in
[clashbox-meta docs/m1a-validation.md](https://github.com/Ghroth6/clashbox-meta/blob/main/docs/m1a-validation.md).

M1a was merged locally on 2026-10-06 into this repository's existing default
branch `codex/ohos-adaptation` and the application's `main`; these merges have
not been pushed, so use the local application checkout for the current contract.
The accepted device evidence and observation limits are recorded in that
repository's `docs/verification/m1a-2026-10-06.md`: 20/20 behavior and recording
checks passed, while 25 socket comparisons remain explicitly unverified.
This milestone validates the configuration operation, not VPN forwarding.

Format decoding invokes real Mihomo `config.UnmarshalRawConfig`. The original
YAML scope gate runs before semantic constructors. Supported static ss/select/
DOMAIN/MATCH inputs pass `config.ValidateMobileStatic`, which checks required
node scalars and integer ports 1..65535, reuses real proxy/group/rule semantics,
then closes and joins all candidate resources before returning. Missing members
and targets return sanitized structured diagnostics. Unsupported fields/resources
remain incomplete. This path never invokes `ParseRawConfig`, temporarily updates
globals, applies a candidate, starts listeners, or obtains external resources.
Parser error strings are deliberately not returned because they can echo input.

Build provenance must set `-X github.com/metacubex/mihomo/mobile/validation.SourceRevision=<actual-clean-commit>`.
An unstamped build reports `development-unidentified`. No version constant proves
the bytes of a library: record the built library hash alongside the source commit.

`mobile/include/cb_validation.h` describes C ownership. `cb_validate_v1` copies
borrowed inputs; the caller must free every returned buffer using `cb_free_v1`.
Bounds are 1 MiB for input and 128 UTF-8 bytes for the operation identifier.
No engine objects or Go pointers cross the boundary.

Backend diagnostic tests are not target-app acceptance. The application's real
operation tests and phone page demonstration required by #7/#6 were completed
for the recorded M1a source and artifacts; changes affecting that behavior need
their own relevant validation.

## Internal design and implementation status

The application design, section 15, defines the product-facing responsibilities.
This section owns the core's internal structure. Existing code below is evidence
of implementation, not evidence that the new application's VPN path works.
The runtime design is a proposal for M1b and later increments; it does not add
exports or change the accepted M1a ABI.

### Implemented validation operation

| Internal responsibility | Current implementation | Ownership and failure rule |
| --- | --- | --- |
| C boundary | `cmd/mobile/main.go`, `mobile/include/cb_validation.h` | Check pointer/size inputs, copy borrowed bytes, serialize receipt into caller-freed output; no retained caller pointers or engine objects |
| Validation operation | `mobile/validation/validation.go` | Own one request, digest and receipt; decode with the engine, classify original input scope, invoke supported semantics, return covered/uncovered capabilities |
| Static semantic construction | `config/mobile_validation.go` | Validate required scalars and supported fields before reusing actual proxy/group/rule constructors; never publish a running configuration |
| Temporary resource ownership | `component/configresources` | Register constructed resources, close and wait before returning; cleanup failure prevents a passing validation receipt |

The call is synchronous inside the C export. Application asynchronous scheduling
does not imply that the engine operation is cancellable. A detached page must not
cause the native caller to abandon output ownership. The application contract
defines how late receipts are ignored while the adapter completes cleanup.

This operation owns no active configuration, provider scheduler, listener or VPN.
An unsupported input is incomplete rather than validated by a shallower fallback.
The temporary resource set cannot escape as a runnable candidate. Runtime setup
must construct and own its own resources; it must not reuse discarded validation
objects. M1b must first extend real checks for any additional required fields.

Module tests exercise `Validate` and the semantic/resource interfaces, including
invalid references, unsupported fields and construction/cleanup failures. C
boundary and application tests separately verify buffer ownership and propagation.
Only the recorded target-app validation proves the accepted device behavior.

### Proposed runtime structure

Use the engine's existing protocol, rule, DNS and connection implementations.
Do not rebuild every upstream package to imitate the application's module list.
The mobile integration must expose the following distinct lifetimes behind its
narrow operation interface:

| Internal responsibility | Private state and collaboration | Required observable behavior |
| --- | --- | --- |
| Mobile runtime operations | Version/capability validation, operation identity, serialization of conflicting engine changes, receipt encoding | Report actual phase, applied identity and cleanup status; no application subscription or UI policy |
| Configuration construction and retirement | Constructed candidate resources, current applied configuration, provider/test tasks and retirement records | Failed construction releases its resources; replacement reports whether old resources were retired and what is now usable |
| Forwarding admission and entries | Runtime generation, ingress readiness, forwarding tasks/connections, pending closes | Entry acceptance is separate from construction; stop rejects new ingress and waits for owned work without cancelling independent management work |
| Platform collaboration | Registered network snapshots and socket-protection callback lifetime | Use the matching live generation; failed protection does not release an unprotected proxy connection; unregister only after required in-flight work is resolved |
| Management execution | Explicit task/route identity, downloads, provider or test work owned by its designated scope | No hidden direct fallback or VPN startup; choose one actual update scheduler per resource and report publication/results |
| Observation and node operations | Engine-derived identities, bounded event delivery, query snapshots and operation results | Reconnecting clients can resynchronize; slow observers do not block forwarding; actual selection/close outcomes are returned |

The application supplies policy and candidate identity; the core must retain
enough immutable configuration data to identify the bytes actually applied.
Application edits must not change runtime data by overwriting a shared file.
Entry stop, configuration retirement, management-task cancellation and complete
engine shutdown are different operations. Some tasks belong to a configuration
and must retire with it; independence from forwarding does not make those tasks
immortal or transferable to a different configuration.

The existing `hub/executor` application/retirement code,
`component/configresources`, forwarding lifecycle, DNS external-ingress control,
platform-network snapshots and subscription APIs documented in the root README
are candidate implementation building blocks. Audit each used path for globals,
concurrent access and ownership before exporting it. In particular, current
listener lifecycle coverage does not prove TUN/DNS/controller cleanup, and an
event unsubscribe does not necessarily wait for an already selected callback.
A new runtime export must bridge those differences explicitly instead of assuming
that calling the existing functions in sequence establishes a safe lifecycle.

### M1b implementation gate and independent verification

Before implementation, fix the runtime carrier and callback threads, TUN
borrow/transfer/duplication and close responsibilities, protection failure and
shutdown ordering, applied-configuration identity, and the minimal supported
configuration fields. Define the actual versioned runtime ABI with the application
in its M1b contract; this README describes internals rather than duplicating that
wire contract. There is currently no such mobile runtime export established by
M1a's validation entry point.

The first runtime increment needs one controlled configuration and one VPN entry.
It does not require all node management, provider updates or explicit listeners.
Its direct core tests must cover partial construction, duplicate/conflicting
operations, stop during startup, late completion, cleanup failure and re-entry
after confirmed cleanup. Tests of management/forwarding independence are required
when those lifetimes are connected, not inferred from separate names.

Host tests can establish engine behavior and adapter contracts. Real callback
threading, descriptor ownership and platform destruction need target-platform
integration; the complete phone-to-proxy-to-target request and subsequent stop
remain the application M1b/M1c acceptance. Record each reused patch's purpose,
affected path and evidence; neither a design table nor an old host test approves
the entire historical patch set.

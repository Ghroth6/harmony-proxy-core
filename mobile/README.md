# Mobile core boundaries

## Application boundary and node preparation

Link recognition, URI conversion, import limits and selected-node composition
belong to the application. Their implementation and tests now live in
`clashbox-meta/app/nativecore`; this core no longer implements content inspection.
`mobile/bridge` exports the proxy/platform C ABI. `cmd/mobile` builds that API
alone; the application imports the bridge into its own shared-library main
package to compose the unchanged application content ABI. Build explicitly with
`scripts/build-mobile.ps1 -ApplicationBridge <app/nativecore>`, alongside the
documented toolchain and cache arguments. The receipt binds both repositories.
Preparation supplies a deny-only physical dialer and candidate-local proxy lookup.
`WithPhysicalDialerForAPI` replaces only the final physical transport: upstream
`dialer-proxy` keeps its actual route and each node retains its IP/interface/mark/
TFO/MPTCP options. Runtime physical dials borrow the accepted generation and
candidate bootstrap resolver; no global tunnel is borrowed for chain lookup.
Standalone node inspection cannot traverse an already published chain. Adapter
resources are discarded and joined; preparation network attempts are rejected.
Selected-node select/MATCH composition remains an explicit local policy. Both
composed nodes and full original YAML use the same prepared-policy runtime.
The independent manual static validator still constructs its own temporary
selected candidate; historical checks only determine its older coverage labels.
Coverage classification reads the original values without constructing another
candidate. Policy validation also reuses its verified plan's adaptations, so a
second construction or cleanup cannot be hidden after a successful result.

Original policy Plan and Build share the upstream proxy/group graph constructor.
Load-balance, include-all and include-all-proxies use actual upstream members,
filtering and order. Group preferences bind effective member positions of that
graph; construction dependencies do not rewrite original group positions.
Negative/overflowed group timer durations fail the shared upstream parser before
a timer starts. Plan/Validate/Build perform no provider initialization or network
acquisition.

`type: dns` associations capture the candidate's actual DNS service. TCP relays
and UDP query workers borrow that service's existing owner, close on cancellation
and join before the owner finishes; they never consult a later global service.
Ordinary query failures still reply SERVFAIL while the association is active;
cancellation and owner retirement terminate it without a replacement answer.
MASQUE parses fallible node DNS settings before allocating its protocol stack,
so failed preparation leaves no stack workers behind.

Proxy providers use the official parser, cache/payload initialization, refresh
and fallback behavior. Individual initialization failures are logged without
rejecting unrelated entries. Provider fetchers and health checks are bound to
the current runtime; preparation does not fetch. Node DNS registrations and TLS
file watchers are deferred until activation and retired with their node. The
process-private home is bound once by the application; ZeroTier retains its
original lazy persistent store. TLS watch ownership uses fsnotify directly to
close partial starts and join callbacks (the pinned fswatch API cannot do so).
MRS domain/ipcidr rules use the official decoder. GEO updates use the official
stale-first schedule with a runtime context; new complete bytes are validated,
saved and substituted into the active scoped matchers. Failed updates keep the
previous matcher and stopping joins the updater.

OHOS builds select the upstream `no_fake_tcp` option and verify that its
`tcp_stub.go` is compiled instead of the Linux raw-socket implementation.
Hysteria fake-TCP nodes can be prepared alongside usable nodes; actual connection,
URL test or health-check attempts return the upstream unsupported-platform error.
There is no extra constructor-level configuration rejection. Full phone fake-TCP
integration is deferred: raw-socket permission and protected socket ownership
remain unverified. Other Hysteria modes are independent.
Public host regressions cover authenticated two-hop SOCKS5 bytes/destinations,
one protected physical socket, closed preparation admission, upstream group
expansion/selection identity, real file errors and refusal before unowned side
effects. Private replay preserves full inputs and source selections. These do
not establish phone protection, external reachability, every protocol's internal
tasks or complete Mihomo configuration compatibility.

`mobile/network.Controller.Submit` and `cb_network_submit_v1` (contract 1) accept
a complete, strict non-VPN snapshot with a monotonic JS-safe generation,
underlying network ID, DNS endpoints, interfaces, addresses and routes. Validation
precedes changes; active or unresolved runtime ownership prevents replacement.
An accepted transition cancels and joins old management work, atomically
publishes the actual snapshot, resets the SystemResolver and resumes online
management admission. Invalid/stale data never gets echoed as an accepted path.
No public DNS fallback is installed when platform DNS is unavailable.

Runtime contract 5 retains the existing `_v1` C symbol names while explicitly
rejecting contract-1/2/3/4 requests. Required top-level `networkGeneration` is separate
from persistent platform policy. Every runtime input requires the current online
snapshot and available DNS for domain nodes; the receipt records only the
actually accepted positive generation. Protected physical
SystemResolver DNS and QUIC packet sockets are independent of client TUN UDP/DNS.

Public host evidence includes real core inspection → selected composition →
validation → fresh candidate/discard, deny-only preparation, strict budgets and
identities, actual snapshot cancellation/join, protected local DNS → real Trojan
TLS/authentication/traffic → normal-stop cleanup, and protected real QUIC TLS.
These isolated fixtures do not prove external node availability, ordinary OHOS
package integration, browser/TUN traffic or target platform protection.
The policy boundary below serves both full original YAML and composed nodes.
The historical node checkpoint does not establish current full-policy or
fresh-process acceptance.

## Mobile runtime contract

### Upstream TUN reuse checkpoint

The runtime reuses sing-tun's public `NewGVisorStack` and `NewUDPForwarder`,
including its UDP reply writer. The existing channel endpoint and cancellable
fd/poll pumps form the OHOS I/O boundary; no dependency cache patch or additional
TUN fd owner is introduced. We use the public stack constructor rather than the
opaque `Stack` interface so cleanup can call the actual stack's `Wait`.
Candidate-local DNS, packet/flow ownership and connection observations remain
in the mobile adapters. IPv6/UDP admission still follows the accepted runtime
options; this integration does not add ICMP forwarding.

The TCP ownership adapter still uses gVisor's upstream `tcp.Forwarder` directly.
Pinned sing-tun's TCP wrapper does not expose failed-handshake completion or a
join for its asynchronous NewConnection callback. Removing our adapter would
lose the existing construction/callback stop barriers. It is retained for that
specific lifecycle gap, not as a replacement TCP protocol implementation.

The runtime does not enter `listener/sing_tun.New`'s native-fd constructor.
With the pinned sing-tun v0.4.27 on the tested ALN-AL00 / OpenHarmony 7.0.0.105,
an experimental build reached `fdbased.New`, where `unix.Fstat` on the real
VPN fd failed with permission denied. The failed listener closed its duplicate;
the mobile runtime retained and cleaned up its original ownership normally.
This is a measured constructor obstacle in that app context, not a blanket
platform or protocol restriction. A separate Windows host experiment passed
IPv4/IPv6 TCP and UDP round trips through the public `GVisorTun` interface and
the pinned official stack using channel packet I/O; it did not exercise a real
TUN, Mihomo routing or the candidate DNS service. Keep the small platform I/O
boundary, candidate-owned DNS, observation and retirement contracts. Integration
validation is recorded separately from that initial feasibility experiment.
Fixed artifacts, raw evidence and restoration are recorded
in the coordinating repository's
[TUN reuse report](https://github.com/Ghroth6/clashbox-meta/blob/main/docs/delivery/verification/upstream-tun-reuse-2026-10-28.md).
The production integration passed 17 Windows test packages (246 top-level
tests), ordinary ARM64 build/signature checks and one phone's full cached-policy
IPv4 TCP/UDP, DNS attribution and normal-stop path. The application host suite
also passed 625 tests. Exact artifacts, failed sandbox attempts, retained TCP
adapter rationale and device restoration are in the
[integration report](https://github.com/Ghroth6/clashbox-meta/blob/main/docs/delivery/verification/upstream-tun-integration-2026-10-29.md).
These results do not establish phone IPv6, every application/protocol or long
background operation.

### Current wire contract

`mobile/include/cb_runtime.h` and `mobile/runtime/contract.go` are the versioned
runtime value boundary. `cb_runtime_contract_version_v1` returns 5 for a build
with the explicitly selected gVisor runtime, independently of the validation ABI;
without `with_gvisor` it returns 0, so the adapter rejects capability before dup.
The three operations own the TUN duplicate, packet stack and stop cleanup.
Host syscall-boundary tests and ARM64 compilation do not establish target TUN
acceptance. Resolve all runtime symbols and the contract version before dup.

The start request contains exactly `contractVersion:5`, `operationId`, `generation`, `networkGeneration`,
`transferId`, `inputRevision`, `inputDigest`, `runtimeOptions`, `platformPolicy`,
`tunPolicy`, and mandatory `preparedPolicy` for every runtime input.
Generation is a JSON integer 1..INT32_MAX and matches the scalar
C argument. `transferId` is a canonical positive decimal string matching the
independent uint64 C argument; the native adapter allocates strictly increasing
IDs. Input digest is `sha256:` plus 64 lowercase hex digits for the exact bytes.
Operation/input/policy revision identifiers are `[A-Za-z0-9:_-]`, 1..128 bytes.
Duplicate, unknown, missing, null or trailing JSON fields are rejected.

Every input keeps its independently sealed resources, platform and group
preferences in `preparedPolicy`. `runtimeOptions` uses `entry:"system-vpn"`,
`transport:"tcp-udp"`, `udp:true` and `explicitListeners:false`; DNS and IPv6
follow the actual prepared configuration. The current select/MATCH node base
omits both settings, preserving Mihomo defaults `IPv6=true`, `DNS.Enable=false`.
Client UDP ingress does not grant UDP support to a TCP-only physical node.
`platformPolicy` has `revision`, `addressFamily`, `applicationIds`, and the optional
`applicationScope` below. Legacy/include lists have 1..16 distinct valid bundle
IDs, each <=128 bytes; explicit all has an empty list. The IPv4 `tunPolicy` uses
`{address:"10.111.0.1",prefixLength:30,route:"0.0.0.0",routePrefixLength:0,mtu:1500}`.
Enabled IPv6 adds `fd00:111::1/126` and `::/0`
and sets address family `dual`. Enabled DNS uses `10.111.0.2`, plus
`fd00:111::2` with dual ingress; this does not override original DNS AAAA policy.
`resourceDownloads` follows the declared runnable provider intervals and never
authorizes initial resource acquisition during preparation or Start.
`networkGeneration` must be positive and match the actual accepted online
snapshot for every Start. The old fixed-node zero-generation bypass is retired;
even literal-IPv4 nodes require observation of the real underlying network.
Input and request lengths must fit the signed C.int ABI (INT32_MAX); observation receipts retain their separate 1 MiB budget.
Packet queue size is 128, MTU 1500 and transfer record capacity 64. The transient
TCP handshake backlog is 1024, matching pinned sing-tun v0.4.27's gVisor
forwarder. A completed handshake releases its backlog reservation while the
callback retains lifetime ownership until real forwarding returns. Established
TCP connections, retained UDP/NAT flows and DNS waiters have no separate milestone
admission ceiling. Ordinary UDP and UDP DNS share the 128 owned-packet budget;
TCP DNS processes one query at a time per connection. Reply writes are synchronous
and use the real bounded gVisor packet queue, which returns a transport error
when full. Writer counts remain cleanup barriers, independently
of the packet queue and observation/history budgets. Start observes up to 5
seconds and stop up to 10 seconds. Actual cleanup retains ownership beyond those
observation limits.

Receipt fields are always present: `contractVersion`, `coreInstance`, `operationId`, `generation`, `networkGeneration`,
`transferId`, `transferConsumed`, `transferState`, `ownershipFault`,
`candidateDigest`, `inputDigest`, `resourceManifestDigest`, `platformPolicyDigest`,
`groupPreferencesDigest`, `phase`, `outcome`, `cleanup`, `failureCode`,
`stack:"gvisor-ipv4-tcp"`, `mtu:1500`, `forwardingActive`, `tun`, `resources`,
`pendingOwners`, `connections`, and `connectionSnapshot`. Phases are absent/validating/constructing/
starting/running/stopping/stopped/failed; outcomes pending/running/stopped/
rejected/failed; cleanup pending/complete/unknown. Transfer state is consumed,
not-found, or fault. Operation identity and digest are empty before a request
has been decoded; absence does not fabricate a request identity.
`coreInstance` is process-owned, fixed within one Go process and different in a
new process. Identity fields remain strings in every receipt, including absent,
failed, stopped and selected-node runs; an unavailable identity is an empty
string, never an omitted field or fabricated digest. Every accepted runtime,
including resource-free composed nodes, binds all four actual digests;
they never substitute the raw digest for the composed candidate identity.
Before construction `stack` retains its legacy placeholder; accepted runtime
reports `gvisor-ipv4-tcp-udp` or `gvisor-dual-tcp-udp` from its actual packet stack.
An absent specific transfer is unknown, never replaced with
the last run. Duplicate ID or record-capacity faults are retained and block
new runs, even if a separate rejected descriptor close succeeds. At most 64
specific transfers are retained: confirmed clean older records may be evicted,
while any unresolved record remains. A query of an evicted transfer is unknown.

`tun` contains `fd`, `metadataBefore`, `closeAttempted`, `closeResult`,
`afterClose`, `metadataAfter`. Metadata contains `observed`, decimal-string
`device`, `inode`, `rdevice`, and numeric `mode`. These are stat metadata, not a
unique open-file-description identity. Unobserved metadata uses decimal "0"
and mode 0. An unavailable stat observation retains the entered fd's ownership;
only a negative fd or explicit EBADF establishes no supplied descriptor.
`closeResult` is -1 before the attempt or while it remains pending,
0 for returned success, or a positive errno; close occurs at most once.
`afterClose` is not-observed/not-visible/metadata-same/metadata-different/unknown.
Each resource has `kind`, `state` (unacquired/acquired/closing/closed/unknown),
and `closeResult`. Resource kinds are candidate, forwarding, wake-read, wake-write,
packet-stack, tun and policy-services; an unexpected
constructor panic retains construction/unknown.
`pendingOwners` reports actual owned work for `pumps`, `tcpCallbacks`,
`constructions`, `forwarding`; original-source snapshots also observe
`udpFlows`, `udpPackets`, `udpWrites` and `dnsWaiters`. Each query obtains active
connections directly from Mihomo `statistic.DefaultManager.Range`, filtered by
both the actual forwarding context generation and metadata generation, and TUN
ingress. INTERNAL/management and other-run entries are excluded. No independent
active inventory, observed-active admission cap, activity ranking or slot policy
selects this list. Active values are sorted by UUID only for presentation.

`connections` copies tracker UUID `id`, `state:active|history`, `protocol:tcp|udp`,
`sourceAddress`, `sourcePort`, `startedAt` (Unix milliseconds), `targetIPv4`,
`targetAddress`, `addressFamily`, `originalDestination`, `destinationAddress`,
`targetPort`, `rule`, `node`, `upload`, `download` and optional `attribution`.
RawDstAddr supplies the original TUN target; destinationAddress is the resolved
metadata destination. Without RawDstAddr, the metadata target is explicitly marked
originalDestination=false. Empty addresses/zero source port mean unavailable.
UUID plus coreInstance/generation distinguishes source-port reuse across runs.
Counters are tracker-observed bytes, not exact encrypted application-message
accounting. No Go pointer, process UID, credentials, payload or physical proxy
endpoint crosses the bridge.

Runtime 5 adds a separately versioned `readable` local display projection from
TrackerInfo/Metadata and the connection's frozen EgressType. It copies RuleHost,
actual rule payload and ordered chain labels; its first label is the actual leaf
label, not a physical peer. Unknown/control/group egress stays unknown. Invalid
Unicode or projection limits produce an empty `limited` value; no label is
partially truncated or promoted within the chain. Existing technical fields,
original/resolved targets and attribution digests remain independent. The exact
shared schema and pairing rules live only in the application repository's
`docs/design/contracts/vpn-runtime.md`; no configuration or payload is exported.

Output also respects the native 65536-value JSON parser budget. Each connection
costs 24 JSON values plus labels and 6 optional attribution values. 1024 values
are reserved for the bounded root, descriptor/resource/pending-owner values and
at most 16 DNS observations with four addresses each (together below 512).
Byte/node exclusions increment the same activeOmitted/historyOmitted counters;
all registered connections remain admitted and forwarded independently.
The existing fork creation subscription supplies a 16-creation history window,
retaining only accounting references and immutable DNS values. Entries still in
the official registry are not repeated as history. This finite window is not a
complete closed-connection log; old active connections remain queryable even
after their history slot is evicted. Registry removal is not proof that I/O or
platform cleanup joined; bounded accounting references settle at real cleanup.

Required `connectionSnapshot` contains capturedAt (Unix milliseconds), active
(matching source entries), activeOmitted, historyDropped (creation-window
evictions), historyOmitted, dnsFactsDropped and dnsLinksOmitted. Zero capturedAt
means no engine observation. The traversal is not atomic across concurrent
creation/close/I/O, but returned UUIDs are unique. Active and history values share
the existing 1 MiB receipt byte budget; overflow is explicitly counted without
changing forwarding. The ordinary RPC also counts omissions when its surrounding
resource/source facts consume that same wire budget. No pagination is added.

Original-source connections additionally carry optional `attribution`; captured
client TUN DNS carries optional `dns` with at most 16 completed service results,
four retained A/AAAA addresses per result, dropped and saturation indicators.
This observes actual service return values, including nonzero DNS rcodes and
finite errors; it does not measure upstream queries/cache hits or prove client
delivery. A fake-IP indication requires the actual captured mapper's domain
association for every retained address, not range membership; truncated addresses
remain unobserved. The connection binds an unambiguous question/address only at
connection creation, never a later lookup. A value-only UUID-to-DNS supplement
preserves exact positive associations beyond the history window, bounded by the
existing 1 MiB budget for serialized UUID/query values; saturation increments
dnsFactsDropped and never limits active inventory or forwarding. Query removes
facts whose UUID is no longer registered in this run. DNS output first includes copies for
selected connections, then the latest completion-ring results, deduplicated and
sorted by original sequence. Expired/ambiguous results unavailable at creation stay
unassociated; later equivalent questions never replace them. `dropped` continues
to count original completion-ring evictions/saturation, even when a retained copy
is returned; it is never reset by selection. Stopped history belongs to that run;
new generations start empty. Absent observations are unavailable, not zero proof.
Hostnames are lowercased and one final dot removed before UTF-8 SHA256; actual
rule payload and Chain[0] labels use exact UTF-8 bytes. These local identifiers
are correlatable, not anonymized, global node identities or physical peer proof.
The application repository's VPN runtime contract owns the exact fields and
limits. A known creation link not contained in the returned 16 DNS records has
dnsSequence=0, dnsLinkOmitted=true; connectionSnapshot.dnsLinksOmitted counts
these returned connections. Missing/ambiguous/expired creation facts remain
unassociated and are never reconstructed using current DNS mappings. Runtime-5
apps and libraries reject earlier contracts before forwarding and must be paired
by exact tested revisions. This does not resolve the observed browser fake-IP /
actual-IP discrepancy or establish phone acceptance.

Public real-gVisor tests cover the mapping/question/original-rule association,
initial ambiguity and later-query/eviction boundaries, answer/history bounds,
new-generation reset and joined stop. A complete synthetic multi-node/group
source with an explicit member preference and fixed rule-provider file exercises
actual proxy and direct hostname traffic. These fixtures do not establish the
user's private-source coverage, browser/system DNS ownership or phone acceptance.

Entering start consumes every actually valid supplied fd before other checks,
including invalid output pointers. The adapter must never close it after entry.
All ABI status failures and corrupted output require query of the exact transfer.
Query with transfer_id=0 means run-only; positive IDs mean the precise handoff.
ABI status 0 only means a receipt buffer was returned; runtime success is in the
receipt. ABI status 1 is invalid output/buffer ABI arguments, 2 is internal/output
failure. Initialize usable outputs to NULL/0, and free every nonnull returned
buffer with `cb_free_v1`. No Go pointer or candidate crosses this boundary.

The reproducible host entry is `scripts/test-mobile-runtime.ps1`, from a clean
committed checkout, using Windows Go 1.24.5 and already cached pinned dependencies:

```powershell
./scripts/test-mobile-runtime.ps1 -ModuleCache '<existing Go module cache>'
```

If that cache lacks the two pinned Windows-only tailscale modules, pass
`-HostSupplementCache '<separate existing cache>'`; it must contain `certstore`
and `go-winio` at the exact versions in this repository's go.mod. The entry does
not download, alter a cache, or rewrite upstream manifests. Each ignored batch
records source/lock hashes, tool version, arguments and results. It runs real
gVisor SYN/handshake/cancellation and real Mihomo candidate/dialer/retirement
behavior through an injected descriptor syscall boundary, plus the affected
validation, protection, forwarding, tunnel, config, executor and statistics regressions.
The same standard entry includes `mobile/policy` and `mobile/policy/contract`,
including production-shaped node composition, original-policy preparation and
strict prepared identities.
It does not use a race detector or execute real Linux/OHOS descriptor syscalls.
Build actual OHOS bytes with `scripts/build-mobile.ps1`. Its optional
`-Architecture arm64-v8a|x86_64` keeps ARM64 as the default and records the Go
architecture, SDK target, actual ELF machine and tool hashes. ARM64 retains its
existing dynamic TLS model, and AMD64 requires the independently built GD toolchain.
Use `-BuildCache` for a task-specific compilation cache; module versions remain
the root's locked inputs. `scripts/test-mobile-build.ps1` invokes that real
build and independently checks the requested ELF64 shared-object machine and
receipt identity. Both targets use `-tlsmodegd`; `check-mobile-elf.ps1` requires
the actual architecture's TLSDESC relocation and rejects STATIC_TLS or IE TLS.
`test-mobile-elf.ps1` checks the real saved legacy AMD64 failure and existing
ARM64 TLSDESC bytes without compiling. Neither compilation nor ELF validation
proves target loading, TLS compatibility, packet forwarding or cleanup.

On 2026-10-21, the actual legacy stripped AMD64 core failed
`dlopen(RTLD_NOW | RTLD_LOCAL)` on `OpenHarmony-7.0.0.105` with
`initial-exec TLS resolves to dynamic definition`. Its AMD64 ELF carries
`STATIC_TLS` and `R_X86_64_TPOFF64`; that old OHOS Go fork accepts the GD option
but does not implement it for AMD64. The new build gate rejects those bytes.
The independent Go repository owns the AMD64 toolchain repair; new core and
package identities need their own target acceptance. App installation or a
visible UI does not establish core loading, preparation, forwarding or cleanup.

New x86_64 builds require `-ToolchainBuildReceipt` pointing to the Go repository's
immutable make receipt; ARM64 can supply the same receipt. The driver verifies
its `goSha256` and complete `toolSha256` against the actual executables before
compiling and rechecks tools afterward. `toolchainBuildRevision` is the receipt's
actual make source revision, alongside the receipt path/hash. The separately
named `sourceTreeRevisionAtCoreBuild` is only the current GOROOT source state,
not independent proof of how those compiler binaries were built.

Private implementation is `mobile/runtime/manager.go` (immediate consumption,
exact transfer records and finite observations), `descriptor_linux.go` (owned
nonblocking TUN and CLOEXEC wake pipe syscalls), `engine_gvisor.go` (pumps,
stack and cleanup), and `tcp_gvisor.go` (bounded tuple/constructor/callback book).
The book exclusively owns its inner Forwarder, reserves before goroutine
scheduling, and shares constructor admission with Stop's mutex. The cancellation
watcher observes actual WritableEvents registration, then joins before waiter
queue reuse. Cleanup joins pumps and constructors before Stack.Close/Abort,
then callbacks/forwarding before Stack.Wait and fd close. Caller timeout leaves
the worker and ownership intact. Every independent safe close and candidate
retirement starts even if another close remains pending or fails.

TUIC adapter retirement calls the explicit pool Close, which cancels admitted
construction and joins the protocol clients and their workers. An idle client
is removed from selection before its Close runs outside the pool mutex; slow
cleanup must not block unrelated requests or prevent stop cancellation. That
cleanup remains registered with the pool, so final Close still waits for its
actual return and includes its error. The upstream 30-minute idle criterion,
stream selection and stream-limit retry behavior are unchanged.

Every Start independently validates `preparedPolicy` and builds fresh owned
resources through `mobile/policy.Engine.BuildCandidate`. Static validation's
M1b/V2 labels never select a runtime implementation. `executor.PublishMobilePolicy`
transfers the prepared graph, DNS, hosts, sniffer and general semantics without
entering the daemon listener/provider-init path. Explicit activation follows
the accepted network snapshot and protection gate. Unpublished candidates use
Discard; published ones use RetireConfig. Every forwarded root carries its
accepted protection generation and candidate-local policy routing.
Binding an unmarked caller inherits cancellation and that run's policy values.
Failed proxy dialing closes and joins its background peek reader
before releasing the forwarding lease, as does successful relay completion.
Unknown closes block a new run. Run-only Query(g,0), matched to the actual current
operation/generation/transfer, with terminal failed/stopped, nonpending cleanup,
zero pending owners and forwardingActive=false establishes joined core TUN users.
The service can independently destroy that run's platform TUN while preserving
core cleanup errors. A historical global ownership fault can remain on this
actual run's query and still blocks restart; an absent or arbitrary fault transfer
with zero counts never establishes this current-run barrier.

This backend owns `mobile/validation` and the versioned byte-buffer C export in
`cmd/mobile`. The application operation and receipt contract are authoritative in
[clashbox-meta docs/design/contracts/core-validation.md](https://github.com/Ghroth6/clashbox-meta/blob/main/docs/design/contracts/core-validation.md).

M1a was merged locally on 2026-10-06 into this repository's existing default
branch `codex/ohos-adaptation` and the application's `main`; these merges have
not been pushed, so use the local application checkout for the current contract.
The accepted device evidence and observation limits are recorded in that
repository's `docs/delivery/verification/m1a-2026-10-06.md`: 20/20 behavior and recording
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
Input length must fit the signed C.int ABI (INT32_MAX); operation identifiers remain at most 128 UTF-8 bytes.
No engine objects or Go pointers cross the boundary.

Backend diagnostic tests are not target-app acceptance. The application's real
operation tests and phone page demonstration required by #7/#6 were completed
for the recorded M1a source and artifacts; changes affecting that behavior need
their own relevant validation.

## Internal design and implementation status

The application design, section 15, defines the product-facing responsibilities.
This section owns the core's internal structure. Existing code below is evidence
of implementation, not evidence that the new application's VPN path works.
The common prepared-policy runtime and exports are documented above and
preserve the independent manual validation ABI. Broader runtime responsibilities below
remain outside this increment unless their own implementation and evidence are
identified explicitly.

### Implemented validation operation

| Internal responsibility | Current implementation | Ownership and failure rule |
| --- | --- | --- |
| C boundary | `mobile/bridge/main.go`, `mobile/include/cb_validation.h` | Check pointer/size inputs, copy borrowed bytes, serialize receipt into caller-freed output; no retained caller pointers or engine objects |
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
objects. Runtime preparation and independent construction use `mobile/policy`.

Module tests exercise `Validate` and the semantic/resource interfaces, including
invalid references, unsupported fields and construction/cleanup failures. C
boundary and application tests separately verify buffer ownership and propagation.
Only the recorded target-app validation proves the accepted device behavior.

### Broader runtime responsibilities

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

### Runtime contract and independent verification

The application's `docs/design/contracts/vpn-runtime.md` defines runtime ownership
and cross-boundary TUN consumption, socket protection and cleanup semantics.
Its platform-evidence section records the SDK/runtime connection discrepancy.
The fixed compiled header/value contract above is implemented, while those
design inputs and host tests do not establish device acceptance. Consult the local
application checkout for unpublished contract and verification changes.

The first-runtime audit must cover TUN failures before ownership transfer,
partial stack Start failures, ignored Close errors and completion of read/write
tasks after closing their resources. The generic executor updates several
subsystems and does not propagate every listener error; its successful return
alone cannot become a mobile TUN-ready receipt. Preserve the existing static
validation boundary and management/forwarding separation while adding the
narrow runtime operation.

The runtime ABI/value contract, transfer ledger, candidate identity,
protection marker, constructor barriers and joined cleanup above implement the
common mobile carrier. Broader configuration and entry capabilities need their own
ownership and verification before extending it. The P2 protection boundary below
remains an independent capability; registration alone does not start a TUN or
forwarding runtime.

The first runtime increment needs one controlled configuration and one VPN entry.
It does not require all node management, provider updates or explicit listeners.
Its direct core tests must cover partial construction, duplicate/conflicting
operations, stop during startup, late completion, cleanup failure and re-entry
after confirmed cleanup. Tests of management/forwarding independence are required
when those lifetimes are connected, not inferred from separate names.

Host tests can establish engine behavior and adapter contracts. Real callback
threading, descriptor ownership and platform destruction need target-platform
integration; the complete phone-to-proxy-to-target request and subsequent stop
remain application acceptance. Record each reused patch's purpose,
affected path and evidence; neither a design table nor an old host test approves
the entire historical patch set.

### Independent manual static validation

The unchanged validation ABI 1 (`cb_validate_v1` / `mobile/validation.Validate`)
remains available for an explicit manual static check. Selected select/MATCH
inputs use `config.ValidateMobileSelected` → `BuildMobileSelectedCandidate` and
discard their temporary real upstream adapters before returning. The constructor
has no runtime caller. Other supported static shapes use `ValidateMobileStatic`.
Neither operation owns a prepared-policy context or authorizes Start.

Historical `m1b-fixed-ipv4-tcp` and `mobile-proxy-ipv4-tcp-v2` labels remain only
as ABI 1 static coverage descriptions. Narrow legacy checks classify those labels;
they never reject an otherwise supported selected static candidate and never
control runtime defaults, preparation, network observation or socket protection.
The real node constructor retains upstream protocol, scalar and TLS semantics;
explicit integration gaps remain incomplete. The existing validation tests keep
this independent user capability and its truthful coverage boundaries.

`node_policy_runtime_test.go` exercises canonical nodes → production-shaped
composition → Plan/Seal/Validate/BuildCandidate → Start/Stop with real policy,
upstream defaults, independent candidate ownership and joined resources. Existing
Trojan runtime tests use that same prepared-policy path with real isolated TLS,
normal certificate/name/expiry rejection, explicit skip policy, authenticated
traffic, failed protection and cancellation. Packet/UDP/DNS/IPv6 tests exercise
actual gVisor ingress. These host checks do not establish target VPN forwarding,
external reachability or phone cleanup.

### Original core logging

`log/log.go` follows the fixed upstream implementation: ordinary Debug/Info/Warn/
Error messages reach its subscriber stream with original text, and Fatal keeps
its original termination behavior. There is no mobile suppression switch or
typed error replacement. Runtime lifecycle and TUN failures add ordinary log
events with the original errors.

`mobile/logging` subscribes to that stream and `mobile/bridge` exposes
`cb_log_install_v1` in `mobile/include/cb_log.h`. The host installs one process-
lifetime callback; normal levels are 0–3, Fatal/Panic are 4–5 and are delivered
synchronously before termination. Borrowed bytes are valid only during the
callback; it must return promptly and tolerate concurrent invocation. A terminal
logrus hook covers the upstream fatal/panic path, which bypasses subscriptions.
The core does not link HiLog or decide display, filtering, retention or export.

The application registers the callback when it loads the library, independently
of the proxy switch, and owns its HiLog adapter. Core tests cover original long
text, upstream console-level independence, fatal delivery, actual TLS rejection
details and normal Stop. Native/target validation belongs to the application;
host results do not prove phone output or VPN forwarding.
### P2 socket protection boundary

`mobile/protection.Gate` owns callback admission and synchronous borrowing.
`mobile/bridge` initializes one immutable context-aware outbound socket policy;
registration only changes synchronized Gate state. The versioned C functions
and scalar ownership are declared in `mobile/include/cb_protection.h`. Validation
ABI 1 and its buffer ownership remain unchanged. No Go pointer crosses either
boundary; the platform retains its C callback/context until unregister succeeds.

The platform callback runs inside the real `RawConn.Control` validity interval.
It must immediately duplicate the borrowed original, bound its wait, and retain
any submitted duplicate until the actual platform operation completes. The core
never closes a borrowed production original; `net.Dialer` owns it. Callback
statuses 1 through 10, an unknown status, panic, invalid raw connection, closed
admission and stale generation all forbid connecting. Unregister closes admission
first and returns busy while a callback still uses the registration. A late
success during unregister becomes inactive, and replacement is refused until
in-flight callbacks finish and unregister succeeds.

`protection.WithGeneration(ctx, generation)` is the public context marker for
the future mobile runtime. Every mobile forwarding root must carry it before
entering the real engine dialer; child contexts retain it. Marked zero or stale
generations never bypass protection. An unmarked context is independent work
and keeps its existing policy, so the runtime assembler must not submit
unmarked forwarding or infer that a lost marker is management. P3 must verify
that propagation before admitting traffic. Required protection rejects a custom
`NetDialer` that cannot expose the physical socket boundary. The hook preserves
the existing global hook and interface/mark options rather than replacing them.
Both physical TCP and UDP sockets use the real context-aware protection hook.
The internal QUIC adapter resolves addresses and creates a protected packet
socket directly; it does not use an opaque custom NetDialer to bypass the hook.
Arbitrary unsupported custom dialers remain rejected under required protection.

The diagnostic probe creates only an unconnected IPv4 TCP socket, performs no
bind/connect/send, reuses `ProtectSocket`, and closes its original once. Probe
IDs use the low half of uint64; production IDs use the high bit and a monotonic
process counter. Each registration uses a strictly increasing generation from
1 through INT32_MAX. The platform bridge owns its finite queue and wait policy;
the Gate has no asynchronous platform queue or unbounded core-owned waiter.

The latest 32 completed probes expose actual local observations through the C
scalar observation function, also readable after unregister. POSIX reads the
original inode and checks device/inode/socket type after close; unavailable
observations are -1. Windows observes live socket type and the actual close
return, but exposes identity and post-close same-object observation as -1:
it has no stable socket cookie here, and querying a closed Winsock handle can
raise STATUS_INVALID_HANDLE under strict handle verification. Winsock startup
has process lifetime, as in Go's net package. A failed OS close yields cleanup
unknown, never a successful probe. These local observations complement the
platform bridge's duplicate observations; they do not prove that protect ran.

Public module tests cover the real probe socket, failure propagation, bounded
observation history, close admission with an in-flight callback, callback status
validation, marked generation rejection, an actual protected dial to a loopback
listener, independent management, custom transport refusal and preserved
interface policy. Host tests and ARM64 compilation remain separate from target
platform protect, TSFN/environment lifetime and complete phone acceptance.

The original-policy implementation is a separate staged boundary under
`mobile/policy`. Its value-only `contract.Seal` uses sorted UTF-8 object keys and
independent input/resource/platform/preference/candidate identities. `Engine`
opens its trusted resource root outside any runtime request. Pure `Plan`
preserves original group positions and resource declarations, including raw
general IPv6 defaults independently of DNS IPv6. Discovery reads rule and DNS
fields, never arbitrary credentials or display names.

`mobile/include/cb_policy.h` declares original-policy ABI 2; context schema and
planner remain 1. `PlatformPolicy.applicationScope` is optional only for legacy
include values. Explicit `all` requires `applicationIds:[]`; explicit `include`
and legacy absence require 1..16 distinct valid bundle IDs. Unknown/null/empty
scope, missing/null list, empty legacy/include and conflicting all reject.
`Engine` preparation and runtime admission independently enforce this. Sealing
alone computes identities and is not policy admission. Canonical encoding omits
the absent legacy scope; the explicit field sorts after `applicationIds` and
before `revision`, changing platform/candidate identities while retaining raw,
resource and preference identities. Frozen valid legacy/all digest fixtures
and actual application-produced contexts cover both languages. Existing TUN
routes, DNS, physical socket protection and resource cleanup are unchanged;
host tests do not establish the target OS application capture behavior.
Native Context binds the trusted resource root once through
`cb_policy_storage_root_v1`, before any runtime request. `cb_policy_plan_v1`
receives raw bytes plus a strict available-resource array;
`cb_policy_validate_v1` receives the independently sealed prepared context;
`cb_policy_resources_v1` observes the accepted run's actual resource ledger.
Raw/control/result lengths must fit the signed C.int ABI (INT32_MAX). No group, member, resource-count or aggregate-resource admission quota is imposed. Resource byte lengths retain exact JSON integers; explicit source size-limit is honored. No resource
bytes or caller-chosen root cross the runtime request. Empty raw has a typed
invalid result and its actual digest. Unknown/missing/null/duplicate fields,
malformed Unicode and trailing JSON are rejected before typed preparation.

Fixed resources use exact `immutable/<digest>/<kind>.<format>` paths inside the
captured trusted root. Preparation checks regular files, byte bounds, full EOF,
Close and independent digests before compiling all provider rules and geodata.
Classical payloads are checked in full before the upstream parser can skip or
log an invalid rule. GEOIP/MMDB/ASN/GEOSITE readers and matcher caches belong to
the candidate's resource manifest; changing a policy cannot reuse a country
matcher from a different manifest or enter upstream download/global caches.

Prepared MMDB verifies the original metadata and separator, every reachable
search-tree path and every reachable data record using the pinned reader's
decoder and Mihomo's actual country/ASN types. Optional description and shared
or embedded data targets are preserved; upstream `Reader.Verify`'s stricter
sequential layout is not a format requirement. Tree DAG memoization bounds
repeated branches and rejects cycles/depth beyond the IP width. Decoding is
bounded before reflection allocation: metadata 128 KiB, containers 4096 items
and depth 64, each record 65536 decoder visits/1 MiB expanded bytes, database
64 Mi visits/256 MiB expanded bytes and 1 Mi distinct reachable records.
Bad pointers/types/tree/separator and small shared-pointer expansion attacks
fail preparation; validation never re-encodes a resource or changes its digest.

For prepared rule resources, `Fetcher.InitialPrepared` loads verified bytes
without a watcher, request or timer. Runtime activation starts one scheduler;
its first tick waits a full configured interval. Actual updates preserve the
original URL, headers, proxy and strategy, use the accepted protection/network
generation and count every actual GET, including each redirect. The resource
client allows at most five redirects, rejects HTTPS downgrade and strips all
declared headers and generated authorization/cookie/referrer data after an
origin change, including later same-origin hops. Each attempt owns a fresh
connection; ordinary upstream HTTP clients keep their existing behavior.
Only a final 200 with complete bounded EOF and returned Close can be adopted.
Intermediate or final Close errors retain the real object and block clean
retirement. Updates check dependency closure and the source's size-limit before
saving, without a separate total-resource quota. A completed temporary file is
synced, closed, re-hashed and atomically published without replacing an immutable
file; only then can the actual provider strategy adopt it. The ledger separates
initial candidate/manifest identity from acquired, saved and adopted versions.
Its process-wide acquisition count never resets. Cancellation joins scheduler,
physical dial racers and close workers; a Close failure retains the real object
and prevents successful cleanup. Closing the Engine refuses a candidate that
still owns its trusted root. GEO auto-update uses the official stale-first and
interval schedule with this run's context. Verified bytes rebuild all active
country matchers before replacing the candidate's readers; failure keeps the
old version and retirement cancels and joins the updater. Proxy providers use
their official Initial/cache/payload path instead of InitialPrepared; their
initialization and refresh failures retain the official partial-success policy.

The original DNS candidate constructs its own inactive ResolverOwner, real
resolver, enhancer and captured service. Original nameserver policy, fallback,
hosts and resource-scoped GEO/RULE-SET matchers remain bound to this candidate.
Physical node bootstrap captures this same candidate's proxy-server resolver,
or its main resolver when no separate proxy-server nameserver is declared.
Disabled client DNS still has a separate owned system bootstrap resolver using
the actual network snapshot; it does not publish a virtual DNS service. Every
original-policy runtime activates and retires that owner, including DNS-disabled
domain nodes, rather than leaving work in the global system resolver.
`MobileDNSService` and captured packet/connection relay entrypoints never switch
to a mutable global service during an operation. DNS activation precedes client
ingress; cancellation closes admission before waiters join, and retirement
removes the old published resolver, fake-IP mapper, service and source hosts only
after its actual workers/transports have joined. The separate runtime client
implementation connects virtual DNS, bounded UDP and dual IPv6 ingress in the
`with_gvisor` build; a build without that engine cannot start a source policy.

Original `sniffer` settings construct the pinned HTTP/TLS/QUIC dispatcher with
the same candidate's scoped GEO and rule-provider parser. Force/skip matchers,
pure-IP and DNS mapping decisions, ports and global/per-protocol destination
overrides retain their original semantics. Sniffer resource dependencies enter
the fixed Plan closure; preparation neither starts a dispatcher nor fetches a
resource. Publication installs it for the actual owned TCP handler and UDP/NAT
sender. Their cancellation and join also retire pending sniff reads and QUIC
senders. Composed node policies follow the same configured sniffer semantics.

`profile.store-fake-ip` uses `component/fakeip.ScopedPersistence`, not the daemon
cachefile singleton. It borrows the Engine's captured root at the fixed path
`state/fakeip/<raw-sha256-hex>.db`; candidate preferences and run generations do
not change that identity. IPv4/IPv6 prefixes have independent buckets. Pure
Plan/Validate/Build register inactive pools without creating a directory or DB;
explicit activation restores them before opening DNS admission. The DB has a
64 MiB bound. Mapping updates commit synchronously before returning a DNS answer.
A real read/write failure returns `POLICY_FAKEIP_STATE_FAILED`, cancels services
and fails the actual runtime rather than acknowledging an uncommitted mapping.
DNS workers join before the resource session Syncs/Closes the real database.
`policy-services` reports that Close result; unknown Close retains the actual DB,
file and root-owning session and blocks subsequent candidates. Engine.Close
refuses both prepared and active owners until successful Discard/retirement.

Synthetic public host evidence covers strict wire decoding, independent policy
identities, actual fixed provider construction/retirement, manifest-scoped DAT
matchers, original DNS policy through real protected queries, and actual
interval HTTP acquisition/save/adoption with failure retaining the old strategy.
It does not establish the new C exports' OHOS build, current original source
resources, ordinary application restoration, target TUN/browser traffic or full
policy acceptance. Original group health checks retain their original URL,
expected status, interval and lazy policy. Pure publication binds an inactive
owner; explicit activation starts the timer, and failure-triggered checks and
dial races share that same run. Retirement closes admission, cancels the actual
request and waits for physical workers and Close results before discarding the
candidate. Synthetic host fixtures cover original url-test/fallback selection,
lazy refresh after Touch, and cancellation of a real pending HTTP read.
Platform-specific process ownership and other stated adaptations still need
their own target evidence. `profile.tracing` is a retained client field absent as
a runtime switch in pinned Mihomo; platform connection observations remain
owned independently. These checkpoints do not complete #25/#26.
# 应用节点目录接入

Go 嵌入方通过 `bridge.SetPolicyReady` 在首次运行前登记本地选择恢复：provider 初始化结束后、客户端入口开放前调用。`bridge.WithActivePolicy` 按核心进程、运行代次及候选摘要借用当前 `config.Config`；回调不得保留图引用或停止该 manager。运行退休等待借用结束，取消后拒绝新借用。页面、持久化及 C/ArkTS 节点协议归应用桥，不加入 Mihomo 业务层。

选择沿用 `Selector.Set/ForceSet` 的名称语义；仅为选择字符串增加并发读写保护。`Fetcher.LastResult` 公开最近一次完成的更新/未变化/失败及时间，不保存历史，不改变下载调度、失败处理或原始日志。provider 内容发布仍使用已有 `Commit`，只在短回调内读取或选择，不在其中进行网络、文件写入或连接关闭。


# Mobile validation export

This backend owns `mobile/validation` and the versioned byte-buffer C export in
`cmd/mobile`. The application operation and receipt contract are authoritative in
[clashbox-meta docs/m1a-validation.md](https://github.com/Ghroth6/clashbox-meta/blob/integration/m1a-6/docs/m1a-validation.md).

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
operation tests and phone page demonstration remain required by #7/#6.

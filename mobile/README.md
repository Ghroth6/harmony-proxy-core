# Mobile validation export

This backend owns `mobile/validation` and the versioned byte-buffer C export in
`cmd/mobile`. The application operation and receipt contract are authoritative in
[clashbox-meta docs/m1a-validation.md](https://github.com/Ghroth6/clashbox-meta/blob/integration/m1a-6/docs/m1a-validation.md).

Format decoding invokes real Mihomo `config.UnmarshalRawConfig`. It does not
invoke `ParseRawConfig`, apply a candidate, start listeners, or obtain resources.
Format success remains `incomplete`; the semantic slice extends this operation.
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

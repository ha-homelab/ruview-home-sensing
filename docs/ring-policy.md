# Collector RSA policy and retained compiler diagnostics

The collector uses the exact `ring` 0.17.14 source authenticated by
[`collector/ring-policy/source.json`](../collector/ring-policy/source.json).
Its local patch checks the RSA modulus's actual bit length instead of rounding
up to bytes before applying the minimum. It does not change RSA arithmetic,
padding, hashes, exponent validation, or the maximum length.

The native regression uses real PKCS#1/SHA-256 and PSS/SHA-256 signatures:
2040-, 2041- and 2047-bit moduli are rejected; 2048-bit moduli are accepted.
All altered-message controls fail verification. The same 2041- and 2047-bit
fixtures are accepted by the original library, establishing the correction's
effect. The full collector build and its existing test suites remain required.

## Lifetime syntax warnings

On 2026-10-19, Rust 1.96.1 compiling the patched path dependency for macOS ARM64
reported nine `mismatched_lifetime_syntaxes` warnings. These declarations already
exist in the authenticated upstream source. Cargo normally caps diagnostics for
registry dependencies; making this package a local path dependency exposes
them. The RSA policy does not add or change these declarations.

The reviewed locations, relative to the prepared `ring` directory, are:

- `src/polyfill/slice/as_chunks.rs:19`: the chunk view and remainder borrow the
  single input slice.
- `src/polyfill/slice/as_chunks_mut.rs:18`: the two returned mutable views borrow
  disjoint halves made by `split_at_mut`.
- `src/polyfill/slice/as_chunks_mut.rs:60` and `:67`: the shared view and mutable
  chunk iterator borrow `self`.
- `src/arithmetic/bigint/modulus.rs:116`: the modulus view borrows the owner's
  limb storage.
- `src/arithmetic/limbs512/storage.rs:45`: the returned aligned chunk view borrows
  the receiver's checked mutable subslice.
- `src/pkcs8.rs:56` and `:65`: the returned `untrusted::Input` values borrow
  checked ranges of the receiver's template bytes.
- `src/rsa/public_modulus.rs:87` in the patched source: the returned view
  delegates to the borrowed modulus owner.

The x86-64-only `as_chunks_mut.rs:55` and `:73` declarations use the same
receiver-borrow pattern and may produce two additional diagnostics on the
hosted native build. Counts must be taken from that actual target's log rather
than assumed equal to the ARM64 count.

These warnings concern inconsistent lifetime spelling in signatures.
The inferred output lifetime remains tied to the input slice or receiver;
none of these declarations converts it to an unconstrained or static lifetime.
Writing the compiler's suggested `'_` makes the same relationship explicit.
See the [official lint explanation](https://doc.rust-lang.org/rustc/lints/listing/warn-by-default.html#mismatched-lifetime-syntaxes).

The project accepts these specific unchanged readability diagnostics while
keeping the dependency patch limited to the security correction. No `allow`
attribute, reduced warning level, or skipped test is introduced. This disposition
does not cover other diagnostics or establish that all dependency code is free
of memory-safety defects.

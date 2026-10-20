# Selected Debian runtime findings

Review date: 2026-10-19.

The collector's pinned Debian 12.15 ARM64 base produced 121 distinct advisory
IDs in the image scan. This review covers the 45 distinct findings reported
as old medium-or-higher or critical candidates. It examines affected
components, architecture, configuration and actual input paths; it does not
treat every installed package match as an exploitable application defect.
The complete per-ID decisions and primary-source links are in
[`evidence/debian-runtime-review.json`](evidence/debian-runtime-review.json).

The reviewed runtime image is
`docker.io/ruvnet/wifi-densepose@sha256:29e6b4ce1893687de205324c509976c53911eff1abdfce3663256de3b82866d7`.
The maintained final Docker stage replaces `/app/sensing-server` and retains
the base libraries, entrypoint and auxiliary executables. It does not run
APT, add Perl modules or extract application-supplied archives.

The reviewed source is
[`4b21c43ed5dae2c2d621e026069f9a7411d6062b`](https://github.com/ha-homelab/ruview-home-sensing/tree/4b21c43ed5dae2c2d621e026069f9a7411d6062b).
Its successful [collector build](https://github.com/ha-homelab/ruview-home-sensing/actions/runs/39367804957)
retains the actual [build evidence and executable](https://github.com/ha-homelab/ruview-home-sensing/actions/runs/39367804957/artifacts/12240461264).
The archive SHA-256 is
`b284251eeb2552d2357e9bd4ffb62485304877885c049d83ddea9341a37fb5e6`;
the 7,286,648-byte executable SHA-256 is
`3b70c0435652fc67f67bcd4d088c244f7f9939c75995b078125f745e97637367`.
These bytes were independently inspected as ELF data, not executed on an
ARM64 target. The artifact records native tests, source hashes, applied
patches and cross-build output. It is not hardware or sensing-accuracy
evidence.

## What was checked

The inspection verified the OCI layer hashes and merged file inventory,
installed package/source metadata, 703 ELF files, and the new executable.
The image runs as root by default and retains eleven SUID/SGID executables.
Their configured PAM modules and native dependency closure were included;
no finding was dismissed merely because this is a container.

The three retained application binaries link `libc`, `libm` and
`libgcc_s`. The new collector has the same direct library set and no imports
of the affected ACL, PAM, block-device, wide-character pushback, `scanf`,
legacy DNS-print, `wordexp` or CRC-combine functions discussed below.
Library import inspection is combined with source and configuration review;
it does not prove that arbitrary dynamically loaded code is safe.

The pinned upstream server's 71 Rust source files were checked for process
and interpreter entry points. Its three process constructors name `netsh`
with fixed arguments; they do not invoke Perl, GNU tar, gzip, GnuPG or
terminfo tools. Some `netsh` branches compile on Linux and fail when that
program is absent, so they are not described as universally Windows-gated.
The maintained entrypoint starts the application directly.

The base also retains `cog-ha-matter` and `homecore-server`. Their native
imports were inspected, but this review does not certify arbitrary upstream
auxiliary modes, custom entrypoint commands, mounted plugins or operator
shell scripts. Those are not the maintained sensing-server input paths.

## glibc: six findings

- **CVE-2026-5435 and CVE-2026-6238:** the affected legacy DNS diagnostic
  printing APIs are not imported by the applications or any inspected
  ELF consumer. Ordinary `getaddrinfo` use is not that API.
- **CVE-2026-5450:** the trigger is the affected `scanf` `%mc` conversion
  with a large width. The application binaries do not import the `scanf`
  family; no owned request path supplies such a format to a utility.
- **CVE-2026-5928:** the trigger concerns `ungetwc` pushback in the affected
  non-Unicode case. The applications do not import it or link the
  `libstdc++` consumer that does.
- **CVE-2026-6368 and CVE-2026-6791:** no inspected ELF consumer imports
  `wordexp` or `wordfree`, and the maintained process calls do not use
  these shell-expansion APIs.

## Privileged utilities and authentication: ten findings

- **CVE-2026-13595:** vulnerable nested-partition parsing code is installed
  in `libblkid`. The collector does not process disk images or invoke
  block-device tools; its entrypoint does not start udev/udisks or a
  block-device hotplug service.
- **CVE-2026-27456:** SUID `mount` is present, but the base's `fstab` has no
  `user,loop` entry required by the reported race. The maintained
  entrypoint does not create one.
- **CVE-2026-3184:** Bookworm's installed `login` is built from `shadow`,
  not the affected util-linux source. Debian explicitly records this
  package distinction.
- **CVE-2026-54369:** non-privileged `cp`, `install`, `mv`, `sed` and `tar`
  consume `libacl`. None of the eleven SUID/SGID programs, configured PAM
  modules or their resolved native closure imports ACL functions. The
  maintained application does not pass untrusted paths to privileged
  ACL utilities.
- **CVE-2026-54370 and CVE-2026-54371:** the affected `getfacl`, `setfacl`,
  `chacl`, `getfattr` and `setfattr` tools are absent.
- **CVE-2024-10041:** the base's local password fields are locked; the
  application does not use a PAM password verifier or start a PAM login
  service. Adding local passwords or mounting another password database
  would require reassessment of the reported password leak.
- **CVE-2026-54411:** `pam_userdb` is installed but no supplied PAM
  configuration enables it. There is no selected plaintext-userdb
  authentication path.
- **CVE-2026-16742 and CVE-2026-15059:** the affected systemd
  `homed`/`homework` and `oomd` components are absent. A source-package
  association with installed `libudev` does not start those services.

## Perl: fifteen findings

- **CVE-2026-42496, CVE-2026-42497 and CVE-2026-9538:** the affected
  `Archive::Tar` implementation is absent. No symlink, hardlink or
  oversized-entry extraction is delegated to that module.
- **CVE-2026-48962, CVE-2025-15649 and CVE-2026-48959:** `IO::Compress`
  and `IO::Uncompress` are absent. Their output-glob evaluation and ZIP
  header/skip routines are different from the installed GNU gzip CLI.
- **CVE-2026-57433:** `Storable` and its native module are absent; there
  is no selected `thaw`/`retrieve` deserialization path.
- **CVE-2026-7010 and CVE-2026-7017:** `HTTP::Tiny` is absent. Rust HTTP
  client requests do not execute its header or redirect implementation.
- **CVE-2026-8376:** the regex buffer-overflow trigger requires a 32-bit
  Perl build. This image has ARM64 ELF and its installed Perl
  configuration records eight-byte pointers and integers.
- **CVE-2026-13221:** no maintained path compiles a Perl regex containing
  more than 65,535 fixed-string alternatives. Debian also records an
  introduction version newer than the installed interpreter, but this
  decision does not rely on resolving that difference from the broader
  CNA version description.
- **CVE-2026-15534:** no maintained path passes an attacker-controlled
  large subject into the affected Perl regex cache.
- **CVE-2026-19487:** application access and filtering decisions do not
  execute the affected Perl Aho-Corasick matcher.
- **CVE-2026-57432:** there is no exposed Perl `pack`/`unpack` template
  input. The installed interpreter alone does not supply that input path.
- **CVE-2026-12087:** the Perl Socket module is present, but the
  application does not call `Socket::pack_ip_mreq_source` with an
  attacker-controlled short buffer. Rust socket operations are not this
  XS function.

The interpreter is not declared repaired. New Perl modules, custom
`PERL5LIB`, application plugins or operator scripts invalidate the relevant
absence or no-call decisions.

## Compression and archive utilities: eight findings

- **CVE-2023-45853:** Debian documents that this Bookworm zlib package
  does not build the vulnerable MiniZip component. MiniZip is absent
  from the actual image inventory.
- **CVE-2026-27171:** neither the rebuilt collector nor the 703 inspected
  ELF consumers import the affected CRC-combine API. Ordinary CRC and
  decompression are not the reported combine function.
- **CVE-2026-42250:** the affected `bzip2recover` executable is absent;
  installed `libbz2` users do not run that program.
- **CVE-2026-41991:** `gzexe` exists, but the supplied `PATH` resolves the
  installed `mktemp`, avoiding the predictable-name fallback. The
  maintained application does not run `gzexe`.
- **CVE-2026-41992:** the application does not invoke one `gzip -d`
  process with the malicious LZW-then-LZH file sequence that triggers
  the shared decoder-state defect.
- **CVE-2026-18477, CVE-2026-18508 and CVE-2026-5704:** GNU tar is
  installed, but no maintained endpoint invokes its incremental restore,
  `--one-top-level` extraction or archive-inspection/extraction workflow.
  The separate Rust `tar` build dependency is assessed separately.

## Other libraries and verification tools: six findings

- **CVE-2026-18938:** the p11-kit allocation trigger is 32-bit; this
  runtime and library are ARM64 ELF64.
- **CVE-2026-13757:** the p11-kit library is present, but the image has
  no p11-kit RPC server executable/configuration and the maintained
  entrypoint starts no RPC listener. The native applications do not
  link its APT/GnuTLS consumer path.
- **CVE-2025-69720 and CVE-2023-50495:** `infocmp`/`tic` are installed,
  but the maintained application does not invoke them, import the
  affected terminfo-wrapping function or accept terminfo compilation
  requests.
- **CVE-2025-30258:** `gpgv` exists, but the certificate-import program
  is absent and the application does not import OpenPGP subkeys. The
  final runtime stage does not replace the base's Debian keyrings.
- **CVE-2025-68972:** the application does not verify clear-signed
  OpenPGP messages or expose the form-feed/unsigned-text input described
  by the advisory. This does not clear custom GnuPG commands or the
  separate compiler image's package-management workflow.

## Conclusion and change boundary

No confirmed applicable old or critical vulnerability was identified among
these 45 findings in the maintained sensing-server runtime paths.
Vulnerable utility packages remain installed; this review does not call
them patched or promise safety for arbitrary uses.

Keep compatible Debian security updates under review. A different image,
architecture, process command, plugin, authentication database, mount
configuration or input parser requires reassessing the affected rows.
Rust/Cargo, compiler-image, firmware SDK/MbedTLS and Python-container
findings are separate assessments. Newer findings are not silently cleared
by this dated review.

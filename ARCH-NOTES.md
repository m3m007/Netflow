# ARCH-NOTES — building nDPI from source on this Arch host (Phase 2)

Date: 2026-10-05. Host: Arch Linux x86_64, running as root. Build dir: tmpfs at `/mnt/build`
(owner-provided; `size=4G`, already mounted before this session). This note records how the real
`ndpiReader` used by `flow_monitor` was produced and why we build from source instead of a package.

## Why source > apt/pacman package

- **Fresh protocol rules.** nDPI's detection quality is dominated by how current its protocol/risk
  definitions are. The distro/AUR packages lag the upstream `dev` branch, which lands new
  dissectors and risk signals continuously. We pinned the exact commit below so behaviour is
  reproducible and auditable.
- **`--with-maxminddb`.** Building with libmaxminddb lets nDPI itself resolve GeoIP per flow. Our
  server does its own GeoLite2 lookup, but keeping the library flag on matches upstream defaults and
  avoids surprises if a dissector gates on geo metadata. Confirmed in the configure summary:
  `MaxMindDB (GeoIP): yes`.
- **The AUR path exists but we keep the manual build.** After installing `paru`, `paru -S ndpi-git`
  is available as an alternative, but it rebuilds whatever HEAD is at install time with no pin and
  adds an extra moving part. The explicit clone+configure+make below is what prod runs.

## Exact steps executed (all verified live)

```
# A1 — build deps (raggle is NOT an Arch package; pacman said "target not found", dropped it)
pacman -S --noconfirm git base-devel libpcap libgcrypt autoconf automake libtool pkg-config python3
# rust (cargo) is a makedepend for paru only, installed later in Task B; not needed to build nDPI.

# A2 — clone + build into tmpfs
mkdir -p /mnt/build && mountpoint -q /mnt/build || mount -t tmpfs -o size=4G tmpfs /mnt/build
cd /mnt/build && git clone --depth 1 --branch dev https://github.com/ntop/nDPI.git
cd nDPI && ./autogen.sh && ./configure --with-maxminddb && make -j8

# A3 — install system-wide
make install && ldconfig
```

Pinned source revision:

```
commit 6b2a77a87b8163fe8d632c5b6fd9862b00bd229f  "Improve dns exfiltration coverage (#3269)"
nDPI version string: 6.1.0-1-6b2a77a
installed binary:    /usr/sbin/ndpiReader
library:             /usr/lib/libndpi.so -> libndpi.so.6.1.0 (+ libndpi.a)
pkg-config:          /usr/lib/pkgconfig/libndpi.pc (Version: 6.1.0)
linkage:             ldd shows libpcap.so.1 and libmaxminddb.so.0 resolved
```

## Flags validated empirically against the built binary (Task C)

These correct/confirm assumptions in `src/main.rs` (`ndpi_args`) and the README:

- **`-F` emits the `xfer` byte counters.** A loopback capture (`ndpiReader -i lo -s 12 -F -K json -k
  <file>`) produced NDJSON where each flow object contains an `"xfer"` block with `src2dst_bytes`,
  `src2dst_packets`, `src2dst_goodput_bytes`, `dst2src_bytes`, ... plus `iat`, `pktlen`, `plen_bins`.
  This is exactly what `main.rs` L664 comments claim ("-F NEW — enables xfer/iat/pktlen/plen_bins"),
  now confirmed against the real 6.1.0 binary rather than a 5.x sample.
- **`-K` takes the FORMAT, `-k` takes the FILE.** The Phase-2 brief's smoke-test line
  `-K json:/tmp/ndpi_lo.json` fails with `Unknown serialization format. Valid values are: tlv,csv,json`.
  Correct form is `-K json -k /tmp/ndpi_lo.json` — which is what `ndpi_args()` already builds. Do not
  use the colon syntax.
- **`-s <N>` is total capture duration; `-t <N>` is the idle-report threshold.** A run with only
  `-t 15` and no `-s` never self-terminates and flushes nothing when killed by `timeout`. For a
  bounded smoke test use `-s`. `main.rs` uses `-s <window>` correctly.
- **`-V` is the logging level (requires an argument), not a version flag.** `ndpiReader -V` alone
  prints usage and exits 1. Use `ndpiReader --version` (or read the startup banner) for the version.

## How flow_monitor finds the binary

`src/main.rs` calls `Command::new("ndpiReader")` (L1360, L1402) — a plain PATH lookup. `make install`
placed it at `/usr/sbin/ndpiReader`, which is on root's PATH, so the daemon picks up this build with
no config change. If run as a non-root user, ensure `/usr/sbin` is on that user's PATH or symlink the
binary somewhere on-path.

## AUR helper (Task B) — paru

`makepkg` refuses to run as root, so paru was compiled as a dedicated unprivileged user and installed
via `pacman -U`:

```
useradd -m -s /bin/bash aurbuild           # build user (makepkg cannot run as root)
# stage PKGBUILD under a home aurbuild owns, pre-install cargo (its makedepend) as root:
pacman -S --noconfirm rust                 # cargo 1.99.0
runuser -u aurbuild -- env PATH=/usr/sbin:/usr/bin:/bin HOME=/home/aurbuild \
    makepkg --noconfirm --skipchecksums     # produces paru-2.1.0-2-x86_64.pkg.tar.zst
pacman -U --noconfirm paru-2.1.0-2-x86_64.pkg.tar.zst
paru --version   # paru v2.1.0 - libalpm v16.0.1
```

`libalpm.so.16` on the host satisfies paru's `libalpm.so>=14` dependency. paru-debug package strip
emitted a harmless "No debugging symbols" note (release build is stripped) — the main package built
and installed cleanly.

## Reproduce-from-scratch checklist

1. Ensure tmpfs build dir is mounted (`mountpoint /mnt/build`).
2. Run the A1/A2/A3 block above.
3. Verify with `ndpiReader --version`, `ldd /usr/sbin/ndpiReader | grep -E 'pcap|maxmind'`.
4. Re-run the Task C loopback smoke test if you change `ndpi_args()`.
5. `cargo test` (27 tests, sled/network-free) must stay green — it guards argv shape and NDJSON parsing.

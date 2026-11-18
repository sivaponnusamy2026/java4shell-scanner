# Java4Shell Dynamic Probe — CVE-2026-114938

A **dynamic** detector for **CVE-2026-114938 ("Java4Shell")** — the heap buffer
overflow in OpenJDK's AVX-512 `java.util.Base64` decoder.

Unlike a static version/CPU scanner, this build decides the result **empirically,
from inside the JVM under test**. You run `Base64IntrinsicTest` *with* a given
runtime; it inspects that runtime in-process and prints one authoritative line:

```
JAVA4SHELL_RESULT: <EXPLOITABLE|VULNERABLE_VERSION|NOT_AFFECTED> | action=... | ...
```

Everything a caller needs is derived from that line (and the exit code). Run the
file; read its output; that is the result.

## How the verdict is formed (inside the probe)

1. **Version** — reads its own `java.version` and decides whether the build is in
   the affected range (17.0.6+, and all of 21/25/27 below the fix; Oracle 8 EPP
   `-perf`). Java 8/11 and patched builds are not affected.
2. **VM options, read in-process** via `HotSpotDiagnosticMXBean` — no external
   tool, no parsing of `java -version`:
   - **`UseBASE64Intrinsics == true`** → the `-XX:-UseBASE64Intrinsics` workaround
     is **not** in effect and the vulnerable stub is live → **recommend PATCH**,
     regardless of the current CPU (workloads migrate to AVX-512 hosts).
   - **`UseBASE64Intrinsics == false`** → the workaround is active, so the probe
     consults **additional CPU information as a secondary confirmation**
     (negotiated `UseAVX`, Linux `avx512vbmi` flag, CPU model) of whether the
     hardware would be exposed if the flag were ever re-enabled.
   - **`UseAVX`** — `>= 3` means the JVM negotiated AVX-512 for this CPU (the
     condition under which the vulnerable intrinsic is compiled and used).
3. **Exercise** — drives `Base64` decoding in a warm-up loop so C2 actually
   compiles the vectorized intrinsic. A clean completion still prints a verdict; a
   hard JVM crash prints none — which the launcher treats as a strong affected
   signal.

> The probe trusts the JVM's **negotiated `UseAVX`** over the CPU model string.
> In a VM/container where AVX-512 is masked, a Skylake/Cascade-class model name
> may appear while `UseAVX=2` — the probe correctly reports the CPU as not
> reachable, because what the JVM negotiated is what an attacker actually hits.

### Verdicts and actions
| Result | Meaning | `action` |
|---|---|---|
| `EXPLOITABLE` | vulnerable runtime **and** AVX-512 Base64 intrinsic active | `PATCH` |
| `VULNERABLE_VERSION` | vulnerable runtime, intrinsics on but CPU didn't negotiate AVX-512 | `PATCH` |
| `VULNERABLE_VERSION` | vulnerable runtime, workaround on, **hardware IS AVX-512 capable** | `PATCH (workaround is the ONLY safeguard)` |
| `VULNERABLE_VERSION` | vulnerable runtime, workaround on, hardware not capable | `PATCH_WHEN_ABLE` |
| `NOT_AFFECTED` | patched/old runtime, or ARM | `NONE` |

Exit codes: **2** = exploitable, **1** = vulnerable version, **0** = not affected.

## Run it

Requires a Java 8+ runtime (the probe JAR is Java-8 bytecode).

**Directly — test the runtime you launch it with:**
```sh
java -jar dist/java4shell-probe.jar          # human + result line
java -jar dist/java4shell-probe.jar --quiet  # result line only
```

**Via the launchers** (relay the probe's output; the probe must run *under* the
runtime being judged):
```sh
./probe.sh                                  # test default java (PATH / JAVA_HOME)
./probe.sh --java /path/to/java             # test one specific runtime
./probe.sh --dir /opt/jvms                  # run the probe under EVERY JVM under DIR
```
```bat
probe.cmd
probe.cmd --java "C:\jdk\bin\java.exe"
probe.cmd --dir "C:\Program Files\Java"
```

To confirm the workaround path on any host:
```sh
java -XX:-UseBASE64Intrinsics -jar dist/java4shell-probe.jar
```

## Build from source
```sh
./build.sh        # Linux/macOS  -> dist/java4shell-probe.jar
build.cmd         # Windows
```
Source is a single file, `src/Base64IntrinsicTest.java` (Java-8 source level). Fix
thresholds live in `isVulnerableVersion(...)`.

## Scope & limits
- **Per-machine, per-runtime.** To judge a JVM you must run the probe *with* it;
  `--dir` iterates every `bin/java` under a directory. Nothing runs across hosts.
- `UseAVX=3` without a confirmable `avx512vbmi` flag (non-Linux) is reported with
  a "verify VBMI / Ice Lake+/Zen 4+" note — Skylake/Cascade Lake have AVX-512F but
  not VBMI.
- The warm-up loop exercises the real decode path. On a genuinely affected
  JVM+CPU this is the attacker's path; run only where a JVM crash is acceptable.
- Confirm findings against your vendor's advisory — version schemes differ across
  Oracle / Temurin / Corretto / Zulu / Red Hat.

*Fix: upgrade to a patched build (17.0.21.1 / 21.0.13.1 / 25.0.5.1 / 27.0.1.1).
Workaround: `-XX:-UseBASE64Intrinsics` (or `-XX:UseAVX=2`). Reflects advisories as
of 2026-11-18.*

# Java4Shell Dynamic Probe — CVE-2026-114938

A **dynamic** detector for **CVE-2026-114938 ("Java4Shell")** — the heap buffer
overflow in OpenJDK's AVX-512 `java.util.Base64` decoder.

Unlike a static version/CPU scanner, this build decides the result **empirically,
from inside the JVM under test**, and answers one **point-in-time** question:

> Is the vulnerable Base64 path reachable on **this JVM, on this hardware, as
> configured, right now?**

The JVM stays on the hardware it was measured on, so a "what if it were moved to an
AVX-512 host" scenario is deliberately **out of scope**. You run
`Base64IntrinsicTest` *with* a given runtime; it inspects that runtime in-process
and prints one authoritative line:

```
JAVA4SHELL_RESULT: <VULNERABLE|NOT_VULNERABLE> | vulnerableNow=... | ...
```

Everything a caller needs is derived from that line (and the exit code). Run the
file; read its output; that is the result.

## How the verdict is formed (inside the probe)

The result is **`VULNERABLE`** only when **all three** hold at the moment of the
check; if any is false, the bug cannot execute on this host as it stands, so the
result is **`NOT_VULNERABLE`**:

1. **Affected build** — reads its own `java.version`; the build must be in the
   affected range (17.0.6+, and all of 21/25/27 below the fix; Oracle 8 EPP
   `-perf`). Java 8/11 and patched builds are not affected. *(Reported separately
   as `affectedBuild=` so you still see the on-disk version status.)*
2. **`UseBASE64Intrinsics == true`** — read in-process via `HotSpotDiagnosticMXBean`
   (no external tool). If it is `false` — whether set by `-XX:-UseBASE64Intrinsics`
   or auto-disabled by HotSpot on a non-AVX-512 CPU — the vulnerable stub cannot
   run, so the host is **not vulnerable now**.
3. **AVX-512 active (`UseAVX >= 3`)** — also read in-process; on Linux the
   `avx512vbmi` CPU flag is additionally confirmed. Without it the vectorized
   vulnerable path is never used.

It also exercises `Base64` decoding in a warm-up loop so C2 compiles the intrinsic;
a clean run still prints a verdict, while a hard JVM crash prints none — which the
launcher can treat as a strong signal.

> The probe trusts the JVM's **negotiated `UseAVX`** over the CPU model string.
> In a VM/container where AVX-512 is masked, a Skylake/Cascade-class model name
> may appear while `UseAVX=2` — the probe correctly reports the path as not used,
> because what the JVM negotiated is what an attacker actually hits.

### Verdicts
| Result | Meaning |
|---|---|
| `VULNERABLE` | affected build **AND** `UseBASE64Intrinsics=true` **AND** AVX-512 active — the vulnerable path can execute now |
| `NOT_VULNERABLE` | any one of those is false (patched/old build, intrinsics disabled, no AVX-512, or ARM) |

Exit codes: **2** = vulnerable now, **0** = not vulnerable now.

> **Note on patching.** This is a *current-state* check, not patch advice. A JVM
> reported `NOT_VULNERABLE` only because `UseBASE64Intrinsics=false` or the CPU
> lacks AVX-512 is still running an `affectedBuild=true` binary; the `affectedBuild`
> field preserves that fact if you later want to drive patching separately.

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

### Setting JVM flags for the runtime under test

The launchers place JVM flags **before** `-jar` (where the JVM reads them), so you
can model a specific configuration — most usefully the Base64 workaround:

```sh
./probe.sh --intrinsics off          # adds -XX:-UseBASE64Intrinsics (workaround on)
./probe.sh --intrinsics on           # adds -XX:+UseBASE64Intrinsics
./probe.sh --jvm-arg -XX:UseAVX=2    # any flag, repeatable
./probe.sh --jvm-arg -Dfoo=bar --jvm-arg -Xmx64m
./probe.sh -XX:-UseBASE64Intrinsics  # bare -X.../-D... flags are auto-routed to the JVM
```
```bat
probe.cmd --intrinsics off
probe.cmd --jvm-arg -XX:UseAVX=2
```
Flags apply to **every** runtime tested, including each one under `--dir`. Running
the probe directly works too: `java <flags> -jar dist/java4shell-probe.jar`.

> These override what the JVM would negotiate on its own, letting you check
> "would this JVM be vulnerable **if** the intrinsic were (re-)enabled?" — e.g.
> `--intrinsics on` flips `base64Intrinsics=true` even where HotSpot auto-disabled
> it. The verdict still requires AVX-512 to be actually active, so on a non-AVX-512
> CPU it stays `NOT_VULNERABLE`.

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

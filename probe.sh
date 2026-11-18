#!/bin/sh
# Java4Shell DYNAMIC probe launcher (CVE-2026-114938) - Linux/macOS.
#
# The verdict comes entirely from running Base64IntrinsicTest INSIDE the JVM
# under test and reading its "JAVA4SHELL_RESULT:" output line. Because the probe
# must execute under the runtime it is judging, this launcher runs the JAR with
# a chosen java and relays what the probe prints.
#
# Usage:
#   ./probe.sh                       # test the default `java` (PATH / JAVA_HOME)
#   ./probe.sh --java /path/to/java  # test one specific runtime
#   ./probe.sh --dir /opt/jvms       # run the probe under EVERY JVM found under DIR
#   ./probe.sh --quiet               # pass-through to the probe (result line only)
set -eu
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
JAR="$SCRIPT_DIR/dist/java4shell-probe.jar"
[ -f "$JAR" ] || { echo "error: probe jar not found at $JAR (run ./build.sh)" >&2; exit 70; }

JAVA_OVERRIDE=""
DIR=""
PASS=""
while [ $# -gt 0 ]; do
    case "$1" in
        --java) JAVA_OVERRIDE="$2"; shift 2 ;;
        --dir)  DIR="$2"; shift 2 ;;
        *)      PASS="$PASS $1"; shift ;;
    esac
done

find_java() {   # resolve a usable java launcher into $REPLY-ish via echo
    if [ -n "$JAVA_OVERRIDE" ]; then echo "$JAVA_OVERRIDE"; return; fi
    if [ -n "${JAVA_HOME:-}" ] && [ -x "$JAVA_HOME/bin/java" ]; then echo "$JAVA_HOME/bin/java"; return; fi
    command -v java 2>/dev/null || { echo ""; return; }
}

run_one() {     # $1 = java binary
    j="$1"
    echo "=== runtime under test: $j ==="
    # shellcheck disable=SC2086
    "$j" -jar "$JAR" $PASS
}

worst=0
if [ -n "$DIR" ]; then
    [ -d "$DIR" ] || { echo "error: not a directory: $DIR" >&2; exit 70; }
    found=0
    # Find every bin/java under DIR (each is a JVM to test). Read line-by-line so
    # paths containing spaces survive. The here-doc keeps the loop in this shell
    # so $worst/$found persist.
    while IFS= read -r j; do
        [ -n "$j" ] || continue
        found=1
        set +e; run_one "$j"; rc=$?; set -e
        [ $rc -gt $worst ] && worst=$rc
        echo
    done <<EOF
$(find "$DIR" -type f \( -name java -o -name java.exe \) -path '*/bin/*' 2>/dev/null)
EOF
    [ $found -eq 1 ] || { echo "no JVMs (bin/java) found under $DIR" >&2; exit 0; }
    exit $worst
else
    JAVA=$(find_java)
    [ -n "$JAVA" ] || { echo "error: no Java runtime found (set JAVA_HOME or use --java)." >&2; exit 69; }
    set +e; run_one "$JAVA"; rc=$?; set -e
    exit $rc
fi

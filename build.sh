#!/bin/sh
# Build the Java4Shell dynamic probe JAR. Requires a JDK (javac + jar), Java 8+.
set -eu
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
cd "$SCRIPT_DIR"
command -v javac >/dev/null 2>&1 || { echo "error: javac not found (install a JDK)." >&2; exit 69; }
rm -rf build; mkdir -p build dist
if javac --release 8 -d build src/Base64IntrinsicTest.java 2>/dev/null; then :; else
    echo "note: --release 8 unavailable, using default release" >&2
    javac -d build src/Base64IntrinsicTest.java
fi
cat > build/MANIFEST.MF <<'EOF'
Manifest-Version: 1.0
Main-Class: Base64IntrinsicTest
Implementation-Title: Java4Shell Dynamic Probe (CVE-2026-114938)
Implementation-Version: 1.0.0
EOF
jar cfm dist/java4shell-probe.jar build/MANIFEST.MF -C build .
echo "built: dist/java4shell-probe.jar"

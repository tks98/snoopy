#!/bin/sh
# Builds snoopy's Java agent (spike) into java/out: snoopy-agent.jar, which
# the JVM loads, and snoopy-hooks.jar, which the agent's manifest puts on
# the boot class path from the same directory. Needs a JDK 17 or later;
# ASM is downloaded from Maven Central and checked against its SHA-1.
set -eu
cd "$(dirname "$0")"
ASM=9.11.1
mkdir -p lib out
# SHA-256 sums pinned here (Maven Central's own are SHA-1), checked
# against the SHA-1 sums it publishes when they were taken.
fetch() { # artifact sha256
	f=lib/$1-$ASM.jar
	if [ ! -f "$f" ]; then
		curl -sSfL -o "$f.tmp" "https://repo1.maven.org/maven2/org/ow2/asm/$1/$ASM/$1-$ASM.jar"
		mv "$f.tmp" "$f"
	fi
	echo "$2  $f" | sha256sum -c --quiet
}
fetch asm ae4e6e10d59d0a1500317764b21881ad883f8550e33c66e6142f7032c6fb566c
fetch asm-tree 2b15c3c1b288a9fad3bb2cd6d988ba9521554914ed1f2a2029141fa3f483154a
fetch asm-commons 6a5095ec53726156a78b2cd2efd45bc4e877754eca7c234f61224a53d6bfa661
cp=lib/asm-$ASM.jar:lib/asm-tree-$ASM.jar:lib/asm-commons-$ASM.jar

rm -rf out/classes out/hooks out/agent && mkdir -p out/classes out/hooks out/agent
javac --release 17 -d out/classes -cp "$cp" $(find agent/src -name '*.java')
cp -r out/classes/snoopy out/hooks/ && rm -rf out/hooks/snoopy/agent
cp -r out/classes/snoopy out/agent/ && rm -rf out/agent/snoopy/hooks
(cd out/agent && for j in asm asm-tree asm-commons; do jar xf ../../lib/$j-$ASM.jar org; done)
epoch=${SOURCE_DATE_EPOCH:-$(git log -1 --format=%ct 2>/dev/null || echo 946684800)}
date=$(date -u -d "@$epoch" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -r "$epoch" +%Y-%m-%dT%H:%M:%SZ)
cat > out/manifest.txt <<MF
Premain-Class: snoopy.agent.Agent
Agent-Class: snoopy.agent.Agent
Can-Retransform-Classes: true
Boot-Class-Path: snoopy-hooks.jar
MF
# jar adds what it's given in that order: sorted, the same everywhere.
pack() { # jar dir [manifest]
	jarfile=$PWD/$1 manifest=${3:+$PWD/$3}
	(
		cd "$2"
		files=$(find . -type f | LC_ALL=C sort)
		if [ -n "$manifest" ]; then
			jar --create --file "$jarfile" --date="$date" --manifest="$manifest" $files
		else
			jar --create --file "$jarfile" --date="$date" $files
		fi
	)
}
rm -f out/snoopy-agent.jar out/snoopy-hooks.jar
pack out/snoopy-agent.jar out/agent out/manifest.txt
pack out/snoopy-hooks.jar out/hooks
echo "built java/out/snoopy-agent.jar and java/out/snoopy-hooks.jar"

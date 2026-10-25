#!/bin/sh
# Builds snoopy's Java agent (spike) into java/out: snoopy-agent.jar, which
# the JVM loads, and snoopy-hooks.jar, which the agent's manifest puts on
# the boot class path from the same directory. Needs a JDK 21 or later;
# ASM is downloaded from Maven Central and checked against its SHA-1.
set -eu
cd "$(dirname "$0")"
ASM=9.11.1
mkdir -p lib out
fetch() { # artifact sha1
	f=lib/$1-$ASM.jar
	if [ ! -f "$f" ]; then
		curl -sSfL -o "$f.tmp" "https://repo1.maven.org/maven2/org/ow2/asm/$1/$ASM/$1-$ASM.jar"
		mv "$f.tmp" "$f"
	fi
	echo "$2  $f" | sha1sum -c --quiet
}
fetch asm edb29aa0c2da2918ce338fb7b218c21ea138dde2
fetch asm-tree ad2b01f445d65aa84cb65900d1c848d121843986
fetch asm-commons 3707c04c3f7197c3d1d8dbc728b791a58809a59e
cp=lib/asm-$ASM.jar:lib/asm-tree-$ASM.jar:lib/asm-commons-$ASM.jar

rm -rf out/classes out/hooks out/agent && mkdir -p out/classes out/hooks out/agent
javac --release 21 -d out/classes -cp "$cp" $(find agent/src -name '*.java')
cp -r out/classes/snoopy out/hooks/ && rm -rf out/hooks/snoopy/agent
cp -r out/classes/snoopy out/agent/ && rm -rf out/agent/snoopy/hooks
(cd out/agent && for j in asm asm-tree asm-commons; do jar xf ../../lib/$j-$ASM.jar org; done)
cat > out/manifest.txt <<MF
Premain-Class: snoopy.agent.Agent
Agent-Class: snoopy.agent.Agent
Can-Retransform-Classes: true
Boot-Class-Path: snoopy-hooks.jar
MF
jar cfm out/snoopy-agent.jar out/manifest.txt -C out/agent .
jar cf out/snoopy-hooks.jar -C out/hooks .
echo "built java/out/snoopy-agent.jar and java/out/snoopy-hooks.jar"

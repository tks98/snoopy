#!/bin/bash
# Checks the ASM release build.sh bundles into snoopy-agent.jar against the
# OSV database (https://osv.dev), for known vulnerabilities. Scanners can't
# see it: build.sh downloads ASM and copies its classes into the jar, with
# no manifest or lockfile that names it, and Dependabot can't update it.
# Needs curl and jq. Exits 1 if ASM has a known vulnerability.
set -euo pipefail

cd "$(dirname "$0")"
version=$(sed -n 's/^ASM=//p' build.sh)
if [ -z "$version" ]; then
	echo "vulncheck.sh: no ASM= line in java/build.sh" >&2
	exit 2
fi
artifacts=(asm asm-tree asm-commons)
query=$(for a in "${artifacts[@]}"; do
	jq -n --arg name "org.ow2.asm:$a" --arg v "$version" \
		'{package: {ecosystem: "Maven", name: $name}, version: $v}'
done | jq -s '{queries: .}')
result=$(curl -sSf --retry 3 -H 'Content-Type: application/json' -d "$query" https://api.osv.dev/v1/querybatch)
found=0
for i in "${!artifacts[@]}"; do
	ids=$(jq -r ".results[$i].vulns // [] | .[].id" <<< "$result")
	if [ -n "$ids" ]; then
		echo "org.ow2.asm:${artifacts[$i]} $version has known vulnerabilities:" $ids
		echo "  Move ASM= in java/build.sh to a fixed release, with its SHA-256 sums."
		found=1
	fi
done
[ $found -eq 0 ] && echo "ASM $version (${artifacts[*]}): no known vulnerabilities"
exit $found

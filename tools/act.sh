#!/bin/sh
# Runs this repository's GitHub Actions jobs locally, with act
# (https://github.com/nektos/act), on a Linux machine with Docker, as they
# would run for a pull request. For example:
#
#   tools/act.sh -l                                  # list the jobs
#   tools/act.sh -W .github/workflows/ci.yml -j test   # lint, unit tests, build
#   tools/act.sh -W .github/workflows/ci.yml -j integration
#   tools/act.sh -W .github/workflows/ci.yml -j java --matrix jdk:21
#
# -W picks the workflow: without it, a job name such as test runs in every
# workflow that has one, at once, and their Go setups trip over each other
# in act's shared tool cache.
#
# Jobs run in privileged containers sharing the host's PID namespace, as the
# BPF tests need, on the host's own kernel and architecture: both runner
# labels map to an Ubuntu 24.04 image for it, and only the matrix entries
# for the host's architecture run. Other arguments go to act. On a Mac,
# Docker Desktop's Linux kernel has what the BPF tests need.
set -eu
case $(uname -m) in
x86_64) arch=amd64 runner=ubuntu-24.04 ;;
aarch64 | arm64) arch=arm64 runner=ubuntu-24.04-arm ;;
*) echo "act.sh: unsupported architecture $(uname -m)" >&2; exit 1 ;;
esac
image=catthehacker/ubuntu:act-24.04
# act's cache server (for setup-go's cache) listens on the host's network
# address, which containers under Docker Desktop on macOS can't reach, and
# setup-go waits for it: there, go without.
cache=
[ "$(uname -s)" = Darwin ] && cache=--no-cache-server
# shellcheck disable=SC2086 # $cache is one word, or none
exec act pull_request $cache \
	-P ubuntu-24.04=$image -P ubuntu-24.04-arm=$image \
	--container-architecture linux/$arch \
	--container-options "--privileged --pid=host" \
	--matrix runner:$runner \
	"$@"

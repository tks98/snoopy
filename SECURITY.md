# Security

## Reporting a vulnerability

Report it privately, through the repository's Security tab: **Report a
vulnerability** (GitHub's private vulnerability reporting). Please don't open
a public issue for it. Say what's affected, the snoopy version
(`snoopy --version`), and how to reproduce it, and leave out any real traffic
snoopy captured: its output holds whatever the traced programs sent.

Fixes go into the next release. Only the latest release is supported.

## What counts

snoopy runs as root and decodes whatever the programs it traces send, so
these matter most:

- Input that makes snoopy crash, hang or use unbounded memory: HTTP/1, HTTP/2,
  HTTP/3 and QUIC, compressed bodies, gRPC and protobuf, from a traced
  program or the server it talks to.
- Anything in the eBPF program, the Java agent (`--java`) or the kubectl
  plugin that a traced program or a pod could use against the machine.
- `--redact` leaving a secret it says it masks in its output.

That snoopy shows other programs' secrets is what it's for: its output is as
sensitive as the traffic, which [README.md](README.md#security) says.

## Known vulnerabilities in what snoopy uses

The Vulnerability scan workflow (`.github/workflows/vulnscan.yml`) checks the
binaries, their Go toolchain and modules, the Java agent's ASM, and the test
programs' dependencies against the Go vulnerability database and OSV, on
every pull request and daily. It fails on any known vulnerability, whether
snoopy's code reaches it or not. The few deliberate exceptions, in test
programs only, are listed with their reasons in `osv-scanner.toml` files.
CodeQL checks snoopy's own code and its workflows.

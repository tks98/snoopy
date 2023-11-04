# snoopy

## Overview

Snoopy is a tool for tracing and monitoring SSL/TLS connections in applications that use common SSL libraries. It leverages eBPF uprobes to hook into SSL functions, collecting metadata before encryption/decryption. This enables Snoopy to monitor SSL traffic without decryption.

Snoopy supports inspecting traffic from applications that use OpenSSL (libssl.so) or GnuTLS (libgnutls.so).


## Building
Snoopy relies on [gobpf](https://github.com/iovisor/gobpf/tree/master), which are Go bindings for bcc. You will need to install [libbcc](https://github.com/iovisor/bcc/blob/master/INSTALL.md) for your specific kernel.

```
go build -o snoopy
```

## Usage

Snoopy supports two optional flags, --json and --pid.

```bash
sudo ./snoopy --json --pid 1337
```

- `json`: Print TLS information in JSON format.
- `pid`: Only print TLS information from a specific process.

Example

```bash
sudo snoopy --json --pid 1716580

{
    "function": "SSL_READ",
    "process_name": "curl",
    "elapsed_time": 0.022584,
    "pid": 1716580,
    "tid": 1716580,
    "message_size": 1369,
    "result": 0,
    "tls_content": "106.8,\"High\":58335.1...."
}

```
This will print TLS information in JSON format only from process ID 1337.
Not supplying either flag, Snoopy will visually display all intercepted SSL/TLS traffic from all processes that use the OpenSSL library.

```bash
sudo snoopy

[ TLS Message Information ]
+--------------+-----------------+
| DESCRIPTION  | VALUE           |
+--------------+-----------------+
| Timestamp    | 23:26:54.337542 |
| Function     | SSL_READ        |
| Process Name | curl            |
| PID          | 1719190         |
| TID          | 1719190         |
| Message Size | 1369 bytes      |
+--------------+-----------------+
[ TLS Content ]
Open":0.2,"High":0.5,"ChangePercentFromLastMonth":..."}
...
[ End of TLS Message ]
```

## Contributing

Feel free to create issues for bugs and feature requests, or make pull requests to improve the utility.

## License

This project is licensed under the MIT License.

## References 
* https://www.airplane.dev/blog/decrypting-ssl-at-scale-with-ebpf
* https://medium.com/@yunwei356/ebpf-practical-tutorial-capturing-ssl-tls-plain-text-using-uprobe-fccb010cfd64
* https://www.datadoghq.com/blog/ebpf-guide/
* https://blog.px.dev/ebpf-openssl-tracing/

# snoopy

## Overview

Snoopy is a tool for tracing and monitoring SSL/TLS connections in applications that use the OpenSSL library. It uses eBPF uprobes to hook the SSL_read() and SSL_write() functions of libssl.so, allowing it to collect metadata before encryption/decryption takes place. This allows Snoopy to monitor SSL traffic without needing to decrypt it.


## Usage

Snoopy supports two optional flags, --json and --pid.

```bash
sudo snoopy --json --pid 1337
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
    "tls_content": "106.8,\"High\":58335.1,\"ChangePercentFromLastMonth\":36.41,\"Volume\":\"4.01M\"},{\"Date\":\"01/01/2021\",\"Price\":33108.1,\"Open\":28951.7,\"High\":41921.7,\"ChangePercentFromLastMonth\":14.37,\"Volume\":\"5.50M\"
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
Open":0.2,"High":0.5,"ChangePercentFromLastMonth":0,"Volume":"826.25K"},{"Date":"10/01/2010","Price":0.2,"Open":0.1,"High":0.2,"ChangePercentFromLastMonth":210.99,"Volume":"1.11M"}
[ End of TLS Message ]
```

## Contributing

Feel free to create issues for bugs and feature requests, or make pull requests to improve the utility.

## License

This project is licensed under the MIT License.

# wspy is a WebSocket client and server for TestWebSocketPython, written
# with the Python websockets library (Debian and Ubuntu's python3-websockets,
# 10.x, or a newer one from PyPI): it serves WebSocket over TLS on
# 127.0.0.1, echoing what it's sent, connects to itself with
# permessage-deflate, context takeover and 1 KiB windows, sends the messages
# the test looks for, and prints "ok".
import asyncio, ssl, sys
import websockets
from websockets.extensions.permessage_deflate import (
    ClientPerMessageDeflateFactory, ServerPerMessageDeflateFactory)

short = "snoopy decodes WebSocket messages. " * 8
long = "".join("message %d of a long one, with a window of 1 KiB; " % i for i in range(3000))
fragments = ["fragment one, ", "fragment two, ", "fragment three"]

async def echo(ws, path=None):  # 10.x passes the path, later ones don't
    async for m in ws:
        await ws.send(m)

async def main():
    server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_ctx.load_cert_chain(sys.argv[1], sys.argv[2])
    client_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    client_ctx.check_hostname, client_ctx.verify_mode = False, ssl.CERT_NONE
    deflate = {"compression": None, "max_size": None}
    async with websockets.serve(echo, "127.0.0.1", 0, ssl=server_ctx, **deflate,
            extensions=[ServerPerMessageDeflateFactory(server_max_window_bits=10, client_max_window_bits=10)]) as server:
        port = server.sockets[0].getsockname()[1]
        async with websockets.connect("wss://127.0.0.1:%d/echo" % port, ssl=client_ctx, **deflate,
                extensions=[ClientPerMessageDeflateFactory(client_max_window_bits=True)]) as ws:
            for m in (short, short, long, fragments):
                await ws.send(m)  # a list is sent as a frame each
                if await ws.recv() != (m if isinstance(m, str) else "".join(m)):
                    sys.exit("echo differs")
            await ws.close(1000, "done")
    print("ok")

asyncio.run(main())

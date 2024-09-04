# quic-zig

Toy QUIC implementation in Zig(0.13.0).

## Run example
```console
$ git clone https://github.com/naoki9911/quic-zig
$ cd quic-zig
$ git clone -b quic-zig https://github.com/naoki9911/tls13-zig
$ zig build

# in an other terminal
$ cd server
$ go build main.go
$ ./main

# run client
$ ./zig-out/bin/quic-zig
client.ClientImpl(udp.PacketReaderWriterUDP).State.INIT
client.ClientImpl(udp.PacketReaderWriterUDP).State.PROC_INIT_PKT0
DST_CON_ID=
PKT_SRC_CON_ID=b92422d0
client.ClientImpl(udp.PacketReaderWriterUDP).State.PROC_HANDSHAKE
client.ClientImpl(udp.PacketReaderWriterUDP).State.FINISH_HANDSHAKE
client.ClientImpl(udp.PacketReaderWriterUDP).State.HANDSHAKE_DONE
```

## References
- https://asnokaze.hatenablog.com/entry/2019/04/22/000927
- https://tex2e.github.io/blog/protocol/quic-handshake-packet-decrypt


# go-streamguard

[WireGuard](https://www.wireguard.com/) implementation that can wrap `net.Conn` and `net.Listener` sockets. This is particularly useful for point-to-point connections, and would allow the use of the lightweight WireGuard protocol instead of TLS, for example.

As with WireGuard, this package does not handle key management or PKI: it is
up to the user of this package to manage keys for connections.

This package makes one slight modification to the WireGuard protocol: before each WireGuard packet, we prepend the packet with the packet length (encoded as a 2-byte, little endian value, not including the 2-byte length itself). This is because the socket API does not expose the WireGuard packets as segment directly, so it makes integration easily.

This code was originally forked from [Wireguard/wireguard-go](https://github.com/WireGuard/wireguard-go).

Note that this package is experimental, and not suitable for production use.

## TODO

* Benchmarking
* Performance fixes
* Automated tests

## Example Usage

Here are some simplified examples. More detailed, fully working examples can be found in the [examples/](examples/) directory of this repository.

### Wrap a listener

```go
tcpListener, err := net.Listen("tcp", "127.0.0.1:9999")
if err != nil {
    panic(err)
}
defer tcpListener.Close()
listener, err := streamguard.WrapListener(tcpListener)
if err != nil {
    panic(err)
}
// set the peer in the listener
listener.SetPeer(peerPublicKey)
// or after accepting
conn, err := listener.Accept()
if err != nil {
    panic(err)
}
err = conn.(*stremaguard.StreamGuard).SetPeer(peerPublicKey)
if err != nil {
    panic(err)
}
```

### Wrap a connection

```go
conn, err := net.Dial("tcp", "127.0.0.1:9999")
if err != nil {
    panic(err)
}
stream, err := streamguard.WrapStream(conn)
if err != nil {
    panic(err)
}
defer conn.Close()
err = conn.SetPeer(peerPublicKey)
if err != nil {
    panic(err)
}
```
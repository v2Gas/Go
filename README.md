# Gaseous Protocol Library

This repository implements the **Gaseous Protocol** for efficiently packing, compressing, and reconstructing TLS ClientHello and ServerHello messages. The library is suitable for advanced TLS mimicry, fingerprinting, proxying, and tunneling scenarios.

## Features

- **Flexible Compression**: Supports Flate, Gzip, Brotli, Zstd, LZ4, XZ, and LZ4Block algorithms.
- **Template and Fingerprint System**: Encode/decode handshake messages using predefined templates or uTLS fingerprint parameters.
- **Full Compatibility**: Handles TLS ClientHello and ServerHello across TLS 1.2 and 1.3.
- **Extensible**: Easily add new compression algorithms or templates.

---

## Basic Usage

### Packing a ClientHello

```go
import "github.com/v2Gas/Go"

// Assume you have a *tls.Conn (or *utls.UConn) after constructing ClientHello
packed, err := tls.PackClientHelloGaseous(conn)
if err != nil {
    // handle error
}
// packed is a []byte containing the Gaseous protocol message
```

### Unpacking a ClientHello

```go
// On the receiving side:
unpacked, err := tls.UnpackClientHelloGaseous(packed)
if err != nil {
    // handle error
}
// unpacked is the raw ClientHello []byte, suitable for forwarding or analysis
```

### Packing/Unpacking ServerHello

The same pattern applies using `PackServerHelloGaseous` and `UnpackServerHelloGaseous` if implemented.

---

## Protocol Structure

See [SPEC.md](./SPEC.md) for the full protocol definition.

- The protocol wraps handshake messages with a compact header and compresses the payload.
- Supports "raw", "template", and "fingerprint" payload modes.
- Compression is negotiated or fixed by the endpoints.

---

## Integration with uTLS

- The library can reconstruct ClientHello messages using uTLS fingerprints.
- Register new templates with `RegisterGaseousTemplate(id, tmpl)`.

---

## Error Handling

- All decoding/encoding functions return errors for invalid headers, unknown algorithms, or unsupported templates.
- Always validate the return value before further processing.

---

## Security Notes

- **Gaseous does not provide encryption or integrity**. Use it within a secure channel (e.g., TLS, QUIC, SSH) to protect message confidentiality and integrity.

---

## Supported Compression Algorithms

| Value | Name        |
|-------|-------------|
| 0     | None        |
| 1     | Flate       |
| 2     | Gzip        |
| 3     | Brotli      |
| 4     | Zstd        |
| 5     | LZ4         |
| 6     | XZ          |
| 7     | LZ4Block    |

---

## Known Issues & Limitations

- **ClientHello/ServerHello Parsing**: For full fidelity, ensure you are using compatible versions of Go, utls, and this library.
- **Template Registry**: When using template mode (`TemplID > 0`), both endpoints must pre-register the same templates.
- **uTLS Dependency**: The fingerprint-based mode requires [refraction-networking/utls](https://github.com/refraction-networking/utls).
- **No Built-in Negotiation**: Compression and template IDs must be agreed out-of-band.

---

## Contributing

Pull requests, bug reports, and feature suggestions are welcome!

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/foo`)
3. Commit your changes (`git commit -am 'Add foo'`)
4. Push to the branch (`git push origin feature/foo`)
5. Open a pull request

---

## License

[MIT License](./LICENSE)

---

## References

- [GASEOUS-SPEC.md](./GASEOUS-SPEC.md)
- [refraction-networking/utls](https://github.com/refraction-networking/utls)
- [RFC 5246](https://datatracker.ietf.org/doc/html/rfc5246)
- [RFC 8446](https://datatracker.ietf.org/doc/html/rfc8446)

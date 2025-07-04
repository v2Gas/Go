# Gaseous Protocol Specification

## 1. Introduction

The **Gaseous Protocol** is an efficient, extensible handshake message container for TLS ClientHello and ServerHello messages. It is designed for use in advanced TLS mimicry, fingerprinting, and high-performance proxying, supporting advanced compression and template-based message synthesis. The protocol enables easy transport and transformation of TLS handshake messages, including transmission over custom transports or within multiplexed protocols.

This document is the formal protocol specification for **Gaseous**, intended to be compatible with RFC 5246 (TLS 1.2), RFC 8446 (TLS 1.3), and typical TLS record/message formats.

---

## 2. Gaseous Message Format

All Gaseous messages follow this framing:

```
+------------+------------+--------+----------+--------------+-------------------+
| Magic[2]   | Version[1] | Algo[1]|Type[1]   | TemplID[2]   | DataLen[4]        |
+------------+------------+--------+----------+--------------+-------------------+
|         Header (11 bytes total)                                      |
+---------------------+------------------------------------------------+
| Compressed Payload (DataLen bytes)                                   |
+---------------------+------------------------------------------------+
```

**Field descriptions:**
- **Magic**: ASCII "GS" (0x47, 0x53)
- **Version**: Protocol version (currently `0x01`)
- **Algo**: Compression algorithm (see section 3)
- **Type**: Message type (1 = ClientHello, 2 = ServerHello)
- **TemplID**: Template identifier (`0` = raw, `0xFFFF` = parameterized/fingerprint, other values = template based)
- **DataLen**: Length (in bytes, big-endian) of the compressed payload
- **Payload**: The compressed data, format depends on TemplID and Algo

For use on wire or in custom channels, a single-byte record marker (recommended: `0xFE`) may be prepended for multiplexing.

---

## 3. Compression Algorithms

| Value | Name        | Description              |
|-------|-------------|-------------------------|
| 0     | None        | No compression          |
| 1     | Flate       | DEFLATE (RFC 1951)      |
| 2     | Gzip        | GZIP (RFC 1952)         |
| 3     | Brotli      | Brotli (RFC 7932)       |
| 4     | Zstd        | Zstandard               |
| 5     | LZ4         | LZ4 (framed)            |
| 6     | XZ          | XZ/LZMA2                |
| 7     | LZ4Block    | LZ4 block, with 4-byte length prefix |

Compression algorithms must be supported by both endpoints; unsupported algorithms MUST result in a protocol error.

---

## 4. Message Types

| Value | Name         | Description                         |
|-------|--------------|-------------------------------------|
| 1     | ClientHello  | Encapsulated TLS ClientHello        |
| 2     | ServerHello  | Encapsulated TLS ServerHello        |

Other types MAY be defined in future versions.

---

## 5. Template System

- **TemplID = 0:** The payload is a compressed, complete raw ClientHello/ServerHello message as per [RFC 5246](https://datatracker.ietf.org/doc/html/rfc5246) or [RFC 8446](https://datatracker.ietf.org/doc/html/rfc8446).
- **TemplID = 0xFFFF:** The payload is a compressed, serialized structure describing a fingerprint (e.g., uTLS parameter set), and the receiver will reconstruct the handshake message using this fingerprint.
- **TemplID > 0:** The payload is compressed parameters to fill in a registered template; the template registry is negotiated or pre-shared out-of-band.

---

## 6. Payload Encoding

### 6.1 Raw Mode (`TemplID = 0`)

- The payload is the complete TLS ClientHello or ServerHello (binary, as sent on the wire), compressed according to Algo.

### 6.2 Parameterized Mode (`TemplID = 0xFFFF`)

- The payload is a compressed serialized fingerprint parameter set (e.g., JSON or CBOR describing CipherSuites, ALPN, SNI, extensions, etc.)
- The receiver reconstructs the handshake using the provided parameters and a local implementation of the fingerprint generator.

### 6.3 Template Mode (`TemplID > 0`)

- The payload is parameters to fill into a pre-negotiated template.
- The template registry maps TemplID to a template definition; parameters are inserted in a template-specific way.

---

## 7. Error Handling

Receivers MUST validate:
- Magic number
- Version (MUST reject unknown major versions)
- Supported Algo
- Supported Type
- Known template (for TemplID > 0)

If any validation fails, the message MUST be rejected and an error reported.

---

## 8. Example (ClientHello Wrapping)

Suppose a TLS ClientHello is 512 bytes. The sender compresses it with Brotli, yielding 220 bytes, and wraps:

- Magic: "GS"
- Version: 1
- Algo: 3 (Brotli)
- Type: 1 (ClientHello)
- TemplID: 0
- DataLen: 220 (0x000000DC)
- Payload: [220 bytes of Brotli-compressed ClientHello]

Final packet (hex, with recordType 0xFE):
```
FE 47 53 01 03 01 00 00 00 00 00 DC [220 bytes...]
```

---

## 9. Security Notes

- Gaseous does not provide encryption or integrity itself.
- Use inside a secure channel (TLS, QUIC, etc.) for confidentiality and integrity.

---

## 10. Extensibility

- New compression algorithms or message types may be added by allocating new `Algo` or `Type` codes in a backward-compatible way.
- Template system is open to custom registry or dynamic negotiation.

---

## 11. References

- [RFC 5246: The Transport Layer Security (TLS) Protocol Version 1.2](https://datatracker.ietf.org/doc/html/rfc5246)
- [RFC 8446: The Transport Layer Security (TLS) Protocol Version 1.3](https://datatracker.ietf.org/doc/html/rfc8446)
- [RFC 1951: DEFLATE Compressed Data Format Specification version 1.3](https://datatracker.ietf.org/doc/html/rfc1951)
- [RFC 1952: GZIP file format specification version 4.3](https://datatracker.ietf.org/doc/html/rfc1952)
- [RFC 7932: Brotli Compressed Data Format](https://datatracker.ietf.org/doc/html/rfc7932)

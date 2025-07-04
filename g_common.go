package tls

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"io"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
	"github.com/pierrec/lz4/v4"
	"github.com/ulikunitz/xz"
	"github.com/v2Gas/Go/internal/lz4block"
)

// ==== Gaseous Protocol Shared Constants, Types, Structs ====

type GaseousHelloCompressAlgo uint8

const (
	GaseousCompressNone     GaseousHelloCompressAlgo = 0
	GaseousCompressFlate    GaseousHelloCompressAlgo = 1
	GaseousCompressGzip     GaseousHelloCompressAlgo = 2
	GaseousCompressBrotli   GaseousHelloCompressAlgo = 3
	GaseousCompressZstd     GaseousHelloCompressAlgo = 4
	GaseousCompressLZ4      GaseousHelloCompressAlgo = 5
	GaseousCompressXZ       GaseousHelloCompressAlgo = 6
	GaseousCompressLZ4Block GaseousHelloCompressAlgo = 7
)

const (
	GaseousHelloMagic      = "GS"
	GaseousHelloVersion    = 1
	GaseousHelloTypeClient = 1
	GaseousHelloTypeServer = 2

	gaseousHelloHeaderSize = 2 + 1 + 1 + 1 + 2 + 4 // = 11
	recordTypeGaseousHello = 0xfe
	MinGaseousHelloLen     = 12
)

type GaseousHelloHeader struct {
	Magic     [2]byte // "GS"
	Version   uint8   // protocol version
	Algo      uint8   // compression algo
	HelloType uint8   // 1: ClientHello, 2: ServerHello
	TemplID   uint16  // template ID (see template registry)
	DataLen   uint32  // compressed payload length
}

var (
	ErrGaseousMagic    = errorString("gaseous: bad magic")
	ErrGaseousVersion  = errorString("gaseous: bad version")
	ErrGaseousAlgo     = errorString("gaseous: unsupported compression algorithm")
	ErrGaseousTemplate = errorString("gaseous: unknown template ID")
	ErrGaseousTrunc    = errorString("gaseous: truncated/invalid data")
	ErrGaseousType     = errorString("gaseous: unknown hello type")
)

type errorString string

func (e errorString) Error() string { return string(e) }

// HelloTemplate is a minimal "skeleton" that can be filled by parameters.
type HelloTemplate struct {
	Serialized []byte // Minimal template body, or marshaled handshake with placeholders
}

// GaseousTemplateRegistry maps template IDs to minimal Hello templates.
type GaseousTemplateRegistry struct {
	Templates map[uint16]*HelloTemplate
}

// Shared template registry for both client and server.
var gaseousTemplates = &GaseousTemplateRegistry{
	Templates: make(map[uint16]*HelloTemplate),
}

// RegisterGaseousTemplate allows both client and server to register templates.
func RegisterGaseousTemplate(id uint16, tmpl *HelloTemplate) {
	gaseousTemplates.Templates[id] = tmpl
}

// Template filling is shared (for both client/server fallback).
func fillHelloTemplate(tmpl *HelloTemplate, params []byte) []byte {
	buf := make([]byte, len(tmpl.Serialized)+len(params))
	copy(buf, tmpl.Serialized)
	copy(buf[len(tmpl.Serialized):], params)
	return buf
}

// === 通用压缩（客户端打包用） ===

func compressFlate(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	w, _ := flate.NewWriter(&buf, flate.BestCompression)
	_, err := w.Write(data)
	w.Close()
	return buf.Bytes(), err
}

func compressGzip(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	_, err := w.Write(data)
	w.Close()
	return buf.Bytes(), err
}

func compressBrotli(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	w := brotli.NewWriterLevel(&buf, brotli.BestCompression)
	_, err := w.Write(data)
	w.Close()
	return buf.Bytes(), err
}

func compressZstd(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	enc, err := zstd.NewWriter(&buf)
	if err != nil {
		return nil, err
	}
	_, err = enc.Write(data)
	enc.Close()
	return buf.Bytes(), err
}

func compressLZ4(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	w := lz4.NewWriter(&buf)
	_, err := w.Write(data)
	w.Close()
	return buf.Bytes(), err
}

func compressXZ(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	w, err := xz.NewWriter(&buf)
	if err != nil {
		return nil, err
	}
	_, err = w.Write(data)
	w.Close()
	return buf.Bytes(), err
}

// LZ4Block: [4字节原始长度|LZ4Block压缩数据]
func compressLZ4Block(data []byte) ([]byte, error) {
	compressed := make([]byte, 4+len(data)+64)
	binary.BigEndian.PutUint32(compressed[:4], uint32(len(data)))
	n, err := lz4block.Encode(compressed[4:], data)
	if err != nil {
		return nil, err
	}
	return compressed[:4+n], nil
}

// === 通用解压（服务端/客户端解包用） ===

func decompressFlate(data []byte) ([]byte, error) {
	r := flate.NewReader(bytes.NewReader(data))
	defer r.Close()
	return io.ReadAll(r)
}

func decompressGzip(data []byte) ([]byte, error) {
	r, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer r.Close()
	return io.ReadAll(r)
}

func decompressBrotli(data []byte) ([]byte, error) {
	r := brotli.NewReader(bytes.NewReader(data))
	return io.ReadAll(r)
}

func decompressZstd(data []byte) ([]byte, error) {
	decoder, err := zstd.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer decoder.Close()
	return io.ReadAll(decoder)
}

func decompressLZ4(data []byte) ([]byte, error) {
	var out bytes.Buffer
	r := lz4.NewReader(bytes.NewReader(data))
	_, err := io.Copy(&out, r)
	return out.Bytes(), err
}

func decompressXZ(data []byte) ([]byte, error) {
	r, err := xz.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	return io.ReadAll(r)
}

func decompressLZ4Block(data []byte) ([]byte, error) {
	if len(data) < 4 {
		return nil, errorString("lz4block: truncated input")
	}
	unSize := binary.BigEndian.Uint32(data[:4])
	dst := make([]byte, unSize)
	n, err := lz4block.Decode(dst, data[4:])
	if err != nil {
		return nil, err
	}
	return dst[:n], nil
}

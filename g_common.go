package tls

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

// Common decompressors
import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"io"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
)

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

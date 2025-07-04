package tls

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"encoding/binary"
	"io"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
	"github.com/pierrec/lz4/v4"
	"github.com/ulikunitz/xz"
)

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
	Magic     [2]byte
	Version   uint8
	Algo      uint8
	HelloType uint8
	TemplID   uint16
	DataLen   uint32
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

type HelloTemplate struct {
	Serialized []byte
}

type GaseousTemplateRegistry struct {
	Templates map[uint16]*HelloTemplate
}

var gaseousTemplates = &GaseousTemplateRegistry{
	Templates: make(map[uint16]*HelloTemplate),
}

func RegisterGaseousTemplate(id uint16, tmpl *HelloTemplate) {
	gaseousTemplates.Templates[id] = tmpl
}

func fillHelloTemplate(tmpl *HelloTemplate, params []byte) []byte {
	buf := make([]byte, len(tmpl.Serialized)+len(params))
	copy(buf, tmpl.Serialized)
	copy(buf[len(tmpl.Serialized):], params)
	return buf
}

// --- Compression functions ---

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

func compressLZ4Block(data []byte) ([]byte, error) {
	// LZ4 block compression with length prefix
	out := make([]byte, 4+len(data)*2)
	binary.BigEndian.PutUint32(out[:4], uint32(len(data)))
	// lz4.CompressBlock expects a hashTable, pass nil for default (slow but simple)
	n, err := lz4.CompressBlock(data, out[4:], nil)
	if err != nil {
		return nil, err
	}
	return out[:4+n], nil
}

// --- Decompression functions ---

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
	n, err := lz4.UncompressBlock(data[4:], dst)
	if err != nil {
		return nil, err
	}
	return dst[:n], nil
}

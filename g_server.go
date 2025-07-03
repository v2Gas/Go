package tls

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"encoding/binary"
	"errors"
	"io"

	// Optional: import only when these dependencies are present in your go.mod
	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
	"github.com/pierrec/lz4/v4"
	"github.com/v2Gas/Go/internal/lz4block"
	"github.com/ulikunitz/xz"
)

// GaseousHelloCompressAlgo identifies the compression algorithm used for (Server/Client)Hello.
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
	// Add more as needed
)

const (
	GaseousHelloMagic   = "GS"
	GaseousHelloVersion = 1
	GaseousHelloTypeClient = 1
	GaseousHelloTypeServer = 2
)

// GaseousHelloHeader is the fixed header for compressed Hello messages.
type GaseousHelloHeader struct {
	Magic     [2]byte // "GS"
	Version   uint8   // protocol version
	Algo      uint8   // compression algo
	HelloType uint8   // 1: ClientHello, 2: ServerHello
	TemplID   uint16  // template ID (see template registry)
	DataLen   uint32  // compressed payload length
}

// Size of the fixed header.
const gaseousHelloHeaderSize = 2 + 1 + 1 + 1 + 2 + 4 // = 11

var (
	ErrGaseousMagic    = errors.New("gaseous: bad magic")
	ErrGaseousVersion  = errors.New("gaseous: bad version")
	ErrGaseousAlgo     = errors.New("gaseous: unsupported compression algorithm")
	ErrGaseousTemplate = errors.New("gaseous: unknown template ID")
	ErrGaseousTrunc    = errors.New("gaseous: truncated/invalid data")
	ErrGaseousType     = errors.New("gaseous: unknown hello type")
)

// GaseousTemplateRegistry maps template IDs to minimal Hello templates.
type GaseousTemplateRegistry struct {
	Templates map[uint16]*HelloTemplate
}

// HelloTemplate is a minimal "skeleton" that can be filled by parameters.
type HelloTemplate struct {
	Serialized []byte // Minimal template body, or marshaled handshake with placeholders
}

// The main registry used by the server.
var gaseousTemplates = &GaseousTemplateRegistry{
	Templates: make(map[uint16]*HelloTemplate),
}

// RegisterGaseousTemplate registers a template for a given ID.
func RegisterGaseousTemplate(id uint16, tmpl *HelloTemplate) {
	gaseousTemplates.Templates[id] = tmpl
}

// UnpackServerHelloGaseous unpacks and decompresses the Gaseous ServerHello packet.
// Returns the reconstructed ServerHello bytes.
func UnpackServerHelloGaseous(data []byte) ([]byte, error) {
	if len(data) < gaseousHelloHeaderSize {
		return nil, ErrGaseousTrunc
	}
	hdr := GaseousHelloHeader{}
	copy(hdr.Magic[:], data[:2])
	hdr.Version = data[2]
	hdr.Algo = data[3]
	hdr.HelloType = data[4]
	hdr.TemplID = binary.BigEndian.Uint16(data[5:7])
	hdr.DataLen = binary.BigEndian.Uint32(data[7:11])

	if string(hdr.Magic[:]) != GaseousHelloMagic {
		return nil, ErrGaseousMagic
	}
	if hdr.Version != GaseousHelloVersion {
		return nil, ErrGaseousVersion
	}
	if hdr.HelloType != GaseousHelloTypeServer {
		return nil, ErrGaseousType
	}
	if _, ok := gaseousTemplates.Templates[hdr.TemplID]; !ok {
		return nil, ErrGaseousTemplate
	}
	if int(hdr.DataLen)+gaseousHelloHeaderSize > len(data) {
		return nil, ErrGaseousTrunc
	}
	compressed := data[gaseousHelloHeaderSize : gaseousHelloHeaderSize+int(hdr.DataLen)]

	// Decompress
	decompressed, err := gaseousDecompressData(compressed, GaseousHelloCompressAlgo(hdr.Algo))
	if err != nil {
		return nil, err
	}

	// Combine decompressed params with template
	tmpl := gaseousTemplates.Templates[hdr.TemplID]
	helloMsg := fillHelloTemplate(tmpl, decompressed)
	return helloMsg, nil
}

// gaseousDecompressData handles all supported algorithms and returns the decompressed data.
func gaseousDecompressData(data []byte, algo GaseousHelloCompressAlgo) ([]byte, error) {
	switch algo {
	case GaseousCompressNone:
		return data, nil
	case GaseousCompressFlate:
		return decompressFlate(data)
	case GaseousCompressGzip:
		return decompressGzip(data)
	case GaseousCompressBrotli:
		return decompressBrotli(data)
	case GaseousCompressZstd:
		return decompressZstd(data)
	case GaseousCompressLZ4:
		return decompressLZ4(data)
	case GaseousCompressXZ:
		return decompressXZ(data)
	case GaseousCompressLZ4Block:
		return decompressLZ4Block(data)
	default:
		return nil, ErrGaseousAlgo
	}
}

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
	// This assumes the uncompressed size is stored in the first 4 bytes (big endian)
	// followed by the lz4block-compressed data.
	if len(data) < 4 {
		return nil, errors.New("lz4block: truncated input")
	}
	unSize := binary.BigEndian.Uint32(data[:4])
	dst := make([]byte, unSize)
	n, err := lz4block.Decode(dst, data[4:])
	if err != nil {
		return nil, err
	}
	return dst[:n], nil
}

// fillHelloTemplate reconstructs the Hello bytes from the template and parameters.
func fillHelloTemplate(tmpl *HelloTemplate, params []byte) []byte {
	// For maximal compression, assume template is a minimal byte stream with placeholders.
	// For this demo, simply append params to the template.
	buf := make([]byte, len(tmpl.Serialized)+len(params))
	copy(buf, tmpl.Serialized)
	copy(buf[len(tmpl.Serialized):], params)
	return buf
}

// Optionally set default decompression algorithm for server logic.
var gaseousDecompressAlgo = GaseousCompressFlate

func SetGaseousDecompressAlgo(algo GaseousHelloCompressAlgo) {
	gaseousDecompressAlgo = algo
}

func IsGaseousHello(data []byte) bool {
	return len(data) >= 2 && string(data[:2]) == GaseousHelloMagic
}

// For demo/test: decompress any hello (client or server), returning type.
func UnpackAnyGaseousHello(data []byte) (helloType uint8, helloMsg []byte, err error) {
	if len(data) < gaseousHelloHeaderSize {
		return 0, nil, ErrGaseousTrunc
	}
	helloType = data[4]
	switch helloType {
	case GaseousHelloTypeClient:
		return 1, nil, errors.New("not implemented: ClientHello unpack on server side")
	case GaseousHelloTypeServer:
		hello, err := UnpackServerHelloGaseous(data)
		return 2, hello, err
	default:
		return helloType, nil, ErrGaseousType
	}
}

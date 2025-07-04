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

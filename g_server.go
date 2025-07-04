package tls

import (
	"bytes"
	"encoding/binary"
	"errors"
)

// Serverhello unpacking
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

	decompressed, err := gaseousDecompressData(compressed, GaseousHelloCompressAlgo(hdr.Algo))
	if err != nil {
		return nil, err
	}

	tmpl := gaseousTemplates.Templates[hdr.TemplID]
	helloMsg := fillHelloTemplate(tmpl, decompressed)
	return helloMsg, nil
}

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

func IsGaseousHello(data []byte) bool {
	return len(data) >= 2 && string(data[:2]) == GaseousHelloMagic
}

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

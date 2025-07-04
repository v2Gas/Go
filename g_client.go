package tls

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"sort"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
	utls "github.com/refraction-networking/utls"
)

// =================== uTLS ClientHello Database Support ===================

var allUTLSIDs = []utls.ClientHelloID{
	utls.HelloChrome_58, utls.HelloChrome_62, utls.HelloChrome_70, utls.HelloChrome_72,
	utls.HelloChrome_83, utls.HelloChrome_87, utls.HelloChrome_96, utls.HelloChrome_100,
	utls.HelloChrome_102, utls.HelloChrome_106_Shuffle, utls.HelloChrome_115_PQ, utls.HelloChrome_120,
	utls.HelloChrome_120_PQ, utls.HelloChrome_131, utls.HelloChrome_133, utls.HelloFirefox_55,
	utls.HelloFirefox_56, utls.HelloFirefox_63, utls.HelloFirefox_65, utls.HelloFirefox_99,
	utls.HelloFirefox_102, utls.HelloFirefox_105, utls.HelloFirefox_120, utls.HelloIOS_11_1,
	utls.HelloIOS_12_1, utls.HelloIOS_13, utls.HelloIOS_14, utls.HelloAndroid_11_OkHttp,
	utls.HelloEdge_85, utls.HelloEdge_106, utls.HelloSafari_16_0, utls.Hello360_7_5, utls.Hello360_11_0,
	utls.HelloQQ_11_1, utls.HelloChrome_100_PSK, utls.HelloChrome_112_PSK_Shuf,
	utls.HelloChrome_114_Padding_PSK_Shuf, utls.HelloChrome_115_PQ_PSK,
}

type GaseousClientHelloParams struct {
	SpecType  string            // e.g. "HelloChrome_120"
	SNI       string
	ALPN      []string
	Random    []byte
	SessionID []byte
	Other     map[string][]byte // for extra params like KeyShare etc.
}

var gaseousTemplates = &GaseousTemplateRegistry{
	Templates: make(map[uint16]*HelloTemplate),
}

func RegisterGaseousTemplate(id uint16, tmpl *HelloTemplate) {
	gaseousTemplates.Templates[id] = tmpl
}

// =================== ClientHello Packing for Gaseous ===================

func matchUTLSClientHello(clientHelloBytes []byte, sni string, alpn []string) (string, *GaseousClientHelloParams) {
	bestMatch := ""
	var params *GaseousClientHelloParams
	bestScore := 0

	chMsg := &utls.ClientHelloMsg{}
	if !chMsg.Unmarshal(clientHelloBytes) {
		return "", nil
	}

	for _, id := range allUTLSIDs {
		spec, err := utls.UTLSIdToSpec(id)
		if err != nil {
			continue
		}
		score := compareClientHelloSpec(chMsg, &spec, sni, alpn)
		if score > bestScore {
			bestScore = score
			bestMatch = id.Str()
			params = &GaseousClientHelloParams{
				SpecType:  bestMatch,
				SNI:       sni,
				ALPN:      alpn,
				Random:    append([]byte(nil), chMsg.Random...),
				SessionID: append([]byte(nil), chMsg.SessionId...),
				Other:     make(map[string][]byte),
			}
		}
	}
	if bestScore >= 50 && bestMatch != "" && params != nil {
		return bestMatch, params
	}
	return "", nil
}

func compareClientHelloSpec(msg *utls.ClientHelloMsg, spec *utls.ClientHelloSpec, sni string, alpn []string) int {
	score := 0
	if len(msg.CipherSuites) > 0 && len(spec.CipherSuites) > 0 {
		overlap := 0
		for _, x := range msg.CipherSuites {
			for _, y := range spec.CipherSuites {
				if x == y {
					overlap++
				}
			}
		}
		score += overlap * 3
	}
	if len(msg.CompressionMethods) > 0 && len(spec.CompressionMethods) > 0 {
		if bytes.Equal(msg.CompressionMethods, spec.CompressionMethods) {
			score += 8
		}
	}
	// ALPN overlap
	if len(alpn) > 0 && len(spec.Extensions) > 0 {
		var specALPN []string
		for _, ext := range spec.Extensions {
			if e, ok := ext.(*utls.ALPNExtension); ok {
				specALPN = append(specALPN, e.AlpnProtocols...)
			}
		}
		match := 0
		for _, proto := range alpn {
			for _, sproto := range specALPN {
				if proto == sproto {
					match++
				}
			}
		}
		score += match * 4
	}
	// SNI match
	if sni != "" {
		for _, ext := range spec.Extensions {
			if e, ok := ext.(*utls.SNIExtension); ok && e.ServerName == sni {
				score += 10
			}
		}
	}
	// Extension types overlap
	var msgExts, specExts []uint16
	for _, e := range msg.Extensions {
		msgExts = append(msgExts, e.Type())
	}
	for _, e := range spec.Extensions {
		specExts = append(specExts, e.Type())
	}
	sort.Slice(msgExts, func(i, j int) bool { return msgExts[i] < msgExts[j] })
	sort.Slice(specExts, func(i, j int) bool { return specExts[i] < specExts[j] })
	commonExt := 0
	i, j := 0, 0
	for i < len(msgExts) && j < len(specExts) {
		if msgExts[i] == specExts[j] {
			commonExt++
			i++
			j++
		} else if msgExts[i] < specExts[j] {
			i++
		} else {
			j++
		}
	}
	score += commonExt * 2

	if len(msg.Random) == 32 {
		score += 2
	}
	if len(msg.SessionId) == 32 || len(msg.SessionId) == 0 {
		score += 2
	}
	return score
}

func PackClientHelloGaseous(c *Conn) ([]byte, error) {
	sni := c.serverName
	alpn := c.config.NextProtos
	clientHelloBytes := c.hand.Bytes()

	if specStr, params := matchUTLSClientHello(clientHelloBytes, sni, alpn); specStr != "" {
		paramBytes, err := json.Marshal(params)
		if err != nil {
			return nil, err
		}
		compressed, err := compressFlate(paramBytes)
		if err != nil {
			return nil, err
		}
		header := make([]byte, gaseousHelloHeaderSize)
		copy(header[:2], []byte(GaseousHelloMagic))
		header[2] = GaseousHelloVersion
		header[3] = byte(GaseousCompressFlate)
		header[4] = GaseousHelloTypeClient
		binary.BigEndian.PutUint16(header[5:7], 0xffff)
		binary.BigEndian.PutUint32(header[7:11], uint32(len(compressed)))
		return append([]byte{recordTypeGaseousHello}, append(header, compressed...)...), nil
	}

	compressed, err := compressBrotli(clientHelloBytes)
	if err != nil {
		return nil, err
	}
	header := make([]byte, gaseousHelloHeaderSize)
	copy(header[:2], []byte(GaseousHelloMagic))
	header[2] = GaseousHelloVersion
	header[3] = byte(GaseousCompressBrotli)
	header[4] = GaseousHelloTypeClient
	binary.BigEndian.PutUint16(header[5:7], 0)
	binary.BigEndian.PutUint32(header[7:11], uint32(len(compressed)))
	return append([]byte{recordTypeGaseousHello}, append(header, compressed...)...), nil
}

// Compression helpers
func compressBrotli(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	w := brotli.NewWriterLevel(&buf, brotli.BestCompression)
	_, err := w.Write(data)
	if err != nil {
		w.Close()
		return nil, err
	}
	w.Close()
	return buf.Bytes(), nil
}
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

// =================== Gaseous ClientHello Decoding (for proxy/server) ===================
func UnpackClientHelloGaseous(data []byte) ([]byte, error) {
	if len(data) < gaseousHelloHeaderSize+1 {
		return nil, ErrGaseousTrunc
	}
	data = data[1:]
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
	if hdr.HelloType != GaseousHelloTypeClient {
		return nil, ErrGaseousType
	}
	if int(hdr.DataLen)+gaseousHelloHeaderSize > len(data) {
		return nil, ErrGaseousTrunc
	}
	compressed := data[gaseousHelloHeaderSize : gaseousHelloHeaderSize+int(hdr.DataLen)]

	if hdr.TemplID == 0xffff {
		plain, err := decompressFlate(compressed)
		if err != nil {
			return nil, err
		}
		var params GaseousClientHelloParams
		if err := json.Unmarshal(plain, &params); err != nil {
			return nil, err
		}
		return buildUTLSClientHello(&params)
	}

	var plain []byte
	var err error
	switch GaseousHelloCompressAlgo(hdr.Algo) {
	case GaseousCompressNone:
		plain = compressed
	case GaseousCompressFlate:
		plain, err = decompressFlate(compressed)
	case GaseousCompressGzip:
		plain, err = decompressGzip(compressed)
	case GaseousCompressBrotli:
		plain, err = decompressBrotli(compressed)
	case GaseousCompressZstd:
		plain, err = decompressZstd(compressed)
	default:
		return nil, ErrGaseousAlgo
	}
	if err != nil {
		return nil, err
	}

	tmpl := gaseousTemplates.Templates[hdr.TemplID]
	if tmpl == nil {
		return nil, ErrGaseousTemplate
	}
	return fillHelloTemplate(tmpl, plain), nil
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

// =================== Template Filling and uTLS Hello Construction ===================

func fillHelloTemplate(tmpl *HelloTemplate, params []byte) []byte {
	buf := make([]byte, len(tmpl.Serialized)+len(params))
	copy(buf, tmpl.Serialized)
	copy(buf[len(tmpl.Serialized):], params)
	return buf
}

func buildUTLSClientHello(params *GaseousClientHelloParams) ([]byte, error) {
	var id utls.ClientHelloID
	found := false
	for _, x := range allUTLSIDs {
		if x.Str() == params.SpecType {
			id = x
			found = true
			break
		}
	}
	if !found {
		return nil, errors.New("unknown uTLS spec: " + params.SpecType)
	}
	uc := utls.UConn{
		ClientHelloID: id,
	}
	spec, err := utls.UTLSIdToSpec(id)
	if err != nil {
		return nil, err
	}
	if params.SNI != "" {
		for _, ext := range spec.Extensions {
			if e, ok := ext.(*utls.SNIExtension); ok {
				e.ServerName = params.SNI
			}
		}
	}
	if len(params.ALPN) > 0 {
		for _, ext := range spec.Extensions {
			if e, ok := ext.(*utls.ALPNExtension); ok {
				e.AlpnProtocols = append([]string{}, params.ALPN...)
			}
		}
	}
	if len(params.Random) == 32 {
		spec.GetRandom = func() []byte { return params.Random }
	}
	if len(params.SessionID) > 0 {
		spec.GetSessionID = func() []byte { return params.SessionID }
	}

	if err := uc.ApplyPreset(&spec); err != nil {
		return nil, err
	}

	hello := uc.HandshakeState.Hello
	if hello == nil {
		return nil, errors.New("failed to build ClientHello")
	}
	return hello.Marshal(), nil
}

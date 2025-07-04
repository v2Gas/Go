package tls

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"strings"
	"sort"

	utls "github.com/refraction-networking/utls"
)

// ========== 指纹参数结构 ==========
type GaseousClientHelloParams struct {
	SpecType  string            // uTLS 指纹名
	SNI       string
	ALPN      []string
	Random    []byte
	SessionID []byte
	Other     map[string][]byte // 扩展参数预留
}

// ========== uTLS 指纹集 ==========
var allUTLSIDs = []utls.ClientHelloID{
	utls.HelloChrome_58, utls.HelloChrome_62, utls.HelloChrome_70, utls.HelloChrome_72,
	utls.HelloChrome_83, utls.HelloChrome_87, utls.HelloChrome_96, utls.HelloChrome_100,
	utls.HelloChrome_102, utls.HelloChrome_106_Shuffle, utls.HelloChrome_115_PQ, utls.HelloChrome_120,
	utls.HelloChrome_120_PQ, utls.HelloChrome_131, utls.HelloFirefox_55, utls.HelloFirefox_56,
	utls.HelloFirefox_63, utls.HelloFirefox_65, utls.HelloFirefox_99, utls.HelloFirefox_102,
	utls.HelloFirefox_105, utls.HelloFirefox_120, utls.HelloIOS_11_1, utls.HelloIOS_12_1,
	utls.HelloIOS_13, utls.HelloIOS_14, utls.HelloAndroid_11_OkHttp, utls.HelloEdge_85,
	utls.HelloEdge_106, utls.HelloSafari_16_0, utls.Hello360_7_5, utls.Hello360_11_0,
	utls.HelloQQ_11_1, utls.HelloChrome_100_PSK, utls.HelloChrome_112_PSK_Shuf,
	utls.HelloChrome_114_Padding_PSK_Shuf, utls.HelloChrome_115_PQ_PSK,
}

// ========== ClientHello 参数字段完整解析 ==========

type ParsedClientHello struct {
	Version            uint16
	Random             []byte
	SessionID          []byte
	CipherSuites       []uint16
	CompressionMethods []byte
	SNI                string
	ALPN               []string
	Extensions         map[uint16][]byte // raw extension data
}

func parseClientHello(data []byte) (*ParsedClientHello, error) {
	// TLS record layer header: type(1) + ver(2) + len(2) = 5
	// Handshake header: type(1) + len(3) = 4
	if len(data) < 9 {
		return nil, errors.New("too short")
	}
	// Skip record header if present
	offset := 0
	if data[0] == 0x16 && len(data) > 5 && (data[1] == 0x03 && (data[2] >= 0x01 && data[2] <= 0x04)) {
		// Record header found
		recordLen := int(binary.BigEndian.Uint16(data[3:5]))
		if len(data) < 5+recordLen {
			return nil, errors.New("truncated TLS record")
		}
		offset = 5
	}
	hs := data[offset:]
	if len(hs) < 4 {
		return nil, errors.New("truncated handshake")
	}
	if hs[0] != 0x01 { // ClientHello
		return nil, errors.New("not clienthello")
	}
	hsLen := int(hs[1])<<16 | int(hs[2])<<8 | int(hs[3])
	if len(hs)-4 < hsLen {
		return nil, errors.New("truncated handshake body")
	}
	body := hs[4 : 4+hsLen]
	out := &ParsedClientHello{
		Extensions: make(map[uint16][]byte),
	}
	// Version
	if len(body) < 2 {
		return nil, errors.New("truncated version")
	}
	out.Version = binary.BigEndian.Uint16(body[:2])
	i := 2
	// Random
	if len(body[i:]) < 32 {
		return nil, errors.New("truncated random")
	}
	out.Random = append([]byte{}, body[i:i+32]...)
	i += 32
	// SessionID
	if len(body[i:]) < 1 {
		return nil, errors.New("truncated sessionid len")
	}
	sidLen := int(body[i])
	i++
	if len(body[i:]) < sidLen {
		return nil, errors.New("truncated sessionid")
	}
	out.SessionID = append([]byte{}, body[i:i+sidLen]...)
	i += sidLen
	// CipherSuites
	if len(body[i:]) < 2 {
		return nil, errors.New("truncated ciphersuites len")
	}
	csLen := int(binary.BigEndian.Uint16(body[i:]))
	i += 2
	if len(body[i:]) < csLen || csLen%2 != 0 {
		return nil, errors.New("truncated/invalid ciphersuites")
	}
	out.CipherSuites = make([]uint16, csLen/2)
	for j := 0; j < csLen/2; j++ {
		out.CipherSuites[j] = binary.BigEndian.Uint16(body[i : i+2])
		i += 2
	}
	// CompressionMethods
	if len(body[i:]) < 1 {
		return nil, errors.New("truncated compression methods len")
	}
	compLen := int(body[i])
	i++
	if len(body[i:]) < compLen {
		return nil, errors.New("truncated compression methods")
	}
	out.CompressionMethods = append([]byte{}, body[i:i+compLen]...)
	i += compLen
	// Extensions (if any)
	if i == len(body) {
		return out, nil // no extensions
	}
	if len(body[i:]) < 2 {
		return nil, errors.New("truncated extensions len")
	}
	extLen := int(binary.BigEndian.Uint16(body[i:]))
	i += 2
	if len(body[i:]) < extLen {
		return nil, errors.New("truncated extensions body")
	}
	exts := body[i : i+extLen]
	ei := 0
	for ei+4 <= len(exts) {
		extType := binary.BigEndian.Uint16(exts[ei:])
		extL := int(binary.BigEndian.Uint16(exts[ei+2:]))
		ei += 4
		if ei+extL > len(exts) {
			break
		}
		out.Extensions[extType] = exts[ei : ei+extL]
		// SNI (0x00 0x00)
		if extType == 0x0000 {
			parseSNI(exts[ei:ei+extL], out)
		}
		// ALPN (0x00 0x10)
		if extType == 0x0010 {
			parseALPN(exts[ei:ei+extL], out)
		}
		ei += extL
	}
	return out, nil
}

func parseSNI(data []byte, out *ParsedClientHello) {
	if len(data) < 2 {
		return
	}
	listLen := int(binary.BigEndian.Uint16(data[:2]))
	i := 2
	for i+3 <= len(data) && i+listLen <= len(data) {
		typ := data[i]
		nameLen := int(binary.BigEndian.Uint16(data[i+1:]))
		i += 3
		if typ == 0 && i+nameLen <= len(data) {
			out.SNI = string(data[i : i+nameLen])
			return
		}
		i += nameLen
	}
}

func parseALPN(data []byte, out *ParsedClientHello) {
	if len(data) < 2 {
		return
	}
	li := 2
	alpnLen := int(binary.BigEndian.Uint16(data[:2]))
	for li < len(data) && li-2 < alpnLen {
		if li >= len(data) {
			break
		}
		l := int(data[li])
		li++
		if li+l > len(data) {
			break
		}
		out.ALPN = append(out.ALPN, string(data[li:li+l]))
		li += l
	}
}

// ========== 指纹比对用 ==========
func matchUTLSClientHello(clientHelloBytes []byte, _ string, _ []string) (string, *GaseousClientHelloParams) {
	parsed, err := parseClientHello(clientHelloBytes)
	if err != nil {
		return "", nil
	}
	bestMatch := ""
	bestScore := 0
	var params *GaseousClientHelloParams

	for _, id := range allUTLSIDs {
		spec, err := utls.UTLSIdToSpec(id)
		if err != nil {
			continue
		}
		score := 0

		// CipherSuites (顺序相关)
		if len(parsed.CipherSuites) > 0 && len(spec.CipherSuites) > 0 {
			match := 0
			for i := range parsed.CipherSuites {
				if i < len(spec.CipherSuites) && parsed.CipherSuites[i] == spec.CipherSuites[i] {
					match++
				}
			}
			score += match * 4
		}
		// CompressionMethods
		if len(parsed.CompressionMethods) > 0 && len(spec.CompressionMethods) > 0 {
			equal := true
			if len(parsed.CompressionMethods) != len(spec.CompressionMethods) {
				equal = false
			} else {
				for i := range parsed.CompressionMethods {
					if parsed.CompressionMethods[i] != spec.CompressionMethods[i] {
						equal = false
						break
					}
				}
			}
			if equal {
				score += 8
			}
		}
		// ALPN
		if len(parsed.ALPN) > 0 {
			alpnMatch := 0
			for _, ext := range spec.Extensions {
				if e, ok := ext.(*utls.ALPNExtension); ok {
					for _, proto := range parsed.ALPN {
						for _, want := range e.AlpnProtocols {
							if proto == want {
								alpnMatch++
							}
						}
					}
				}
			}
			score += alpnMatch * 4
		}
		// SNI
		if parsed.SNI != "" {
			for _, ext := range spec.Extensions {
				if _, ok := ext.(*utls.SNIExtension); ok {
					score += 3
					break
				}
			}
		}
		if score > bestScore {
			bestScore = score
			bestMatch = id.Str()
			params = &GaseousClientHelloParams{
				SpecType:  bestMatch,
				SNI:       parsed.SNI,
				ALPN:      parsed.ALPN,
				Random:    parsed.Random,
				SessionID: parsed.SessionID,
				Other:     make(map[string][]byte),
			}
		}
	}
	if bestScore >= 10 && bestMatch != "" && params != nil {
		return bestMatch, params
	}
	return "", nil
}

// ========== Pack/Unpack/Build ==========
func PackClientHelloGaseous(c *Conn) ([]byte, error) {
	sni := c.serverName
	alpn := c.config.NextProtos
	clientHelloBytes := c.hand.Bytes()

	// 支持所有压缩算法
	compressFuncs := []struct {
		algo GaseousHelloCompressAlgo
		fn   func([]byte) ([]byte, error)
	}{
		{GaseousCompressFlate, compressFlate},
		{GaseousCompressGzip, compressGzip},
		{GaseousCompressBrotli, compressBrotli},
		{GaseousCompressZstd, compressZstd},
		{GaseousCompressLZ4, compressLZ4},
		{GaseousCompressXZ, compressXZ},
		{GaseousCompressLZ4Block, compressLZ4Block},
	}

	if specStr, params := matchUTLSClientHello(clientHelloBytes, sni, alpn); specStr != "" {
		paramBytes, err := json.Marshal(params)
		if err != nil {
			return nil, err
		}
		for _, cfn := range compressFuncs {
			comp, err := cfn.fn(paramBytes)
			if err == nil {
				header := make([]byte, gaseousHelloHeaderSize)
				copy(header[:2], []byte(GaseousHelloMagic))
				header[2] = GaseousHelloVersion
				header[3] = byte(cfn.algo)
				header[4] = GaseousHelloTypeClient
				binary.BigEndian.PutUint16(header[5:7], 0xffff)
				binary.BigEndian.PutUint32(header[7:11], uint32(len(comp)))
				return append([]byte{recordTypeGaseousHello}, append(header, comp...)...), nil
			}
		}
		return nil, errors.New("all compression failed")
	}

	for _, cfn := range compressFuncs {
		comp, err := cfn.fn(clientHelloBytes)
		if err == nil {
			header := make([]byte, gaseousHelloHeaderSize)
			copy(header[:2], []byte(GaseousHelloMagic))
			header[2] = GaseousHelloVersion
			header[3] = byte(cfn.algo)
			header[4] = GaseousHelloTypeClient
			binary.BigEndian.PutUint16(header[5:7], 0)
			binary.BigEndian.PutUint32(header[7:11], uint32(len(comp)))
			return append([]byte{recordTypeGaseousHello}, append(header, comp...)...), nil
		}
	}
	return nil, errors.New("all compression failed")
}

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
	case GaseousCompressLZ4:
		plain, err = decompressLZ4(compressed)
	case GaseousCompressXZ:
		plain, err = decompressXZ(compressed)
	case GaseousCompressLZ4Block:
		plain, err = decompressLZ4Block(compressed)
	default:
		return nil, ErrGaseousAlgo
	}
	if err != nil {
		return nil, err
	}
	if hdr.TemplID == 0xffff {
		var params GaseousClientHelloParams
		if err := json.Unmarshal(plain, &params); err != nil {
			return nil, err
		}
		return buildUTLSClientHello(&params)
	}
	tmpl := gaseousTemplates.Templates[hdr.TemplID]
	if tmpl == nil {
		return nil, ErrGaseousTemplate
	}
	return fillHelloTemplate(tmpl, plain), nil
}

// ========== uTLS指纹重建 ==========
func buildUTLSClientHello(params *GaseousClientHelloParams) ([]byte, error) {
	var id utls.ClientHelloID
	found := false
	for _, x := range allUTLSIDs {
		if strings.EqualFold(x.Str(), params.SpecType) {
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
	// uTLS随机字段不支持外部注入，后续可补丁
	if err := uc.ApplyPreset(&spec); err != nil {
		return nil, err
	}
	hello := uc.HandshakeState.Hello
	if hello == nil {
		return nil, errors.New("failed to build ClientHello")
	}
	helloBytes, err := hello.Marshal()
	if err != nil {
		return nil, err
	}
	return helloBytes, nil
}

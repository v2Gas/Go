package lz4block

import (
	"errors"

	"github.com/pierrec/lz4/v4"
)

// lz4blockDecode 解码 LZ4 block 格式压缩数据。
// dst: 解压目标缓冲区（必须等于解压后长度）
// src: LZ4 block 格式数据（无frame头尾，直接block压缩体）
// 返回解压后的字节数和错误
func Decode(dst, src []byte) (int, error) {
	n, err := lz4.UncompressBlock(src, dst)
	if err != nil {
		return n, err
	}
	if n != len(dst) {
		return n, errors.New("lz4block: decompressed size mismatch")
	}
	return n, nil
}

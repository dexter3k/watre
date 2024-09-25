package main

import (
	"os"
	"io"
	"encoding/binary"
)

type WatcomExe struct {
	CodeBase uint32
	Code     []byte

	DataBase uint32
	Data     []byte
}

func LoadWatcomExe(path string) (WatcomExe, error) {
	exe := WatcomExe{}

	f, err := os.Open(path)
	if err != nil {
		return exe, err
	}
	d, err := io.ReadAll(f)
	f.Close()
	if err != nil {
		return exe, err
	}

	codeOffset := binary.LittleEndian.Uint32(d[0x18c:][:4])
	codeSize := binary.LittleEndian.Uint32(d[0x188:][:4])

	exe.CodeBase = 0x410000
	exe.Code = make([]byte, codeSize, codeSize)
	copy(exe.Code, d[codeOffset:][:codeSize])

	return exe, nil
}

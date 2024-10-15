package main

import (
	"fmt"
	"encoding/binary"
	"io"
	"os"
	"runtime/pprof"

	"github.com/dexter3k/watre/explore/ext/omf"
)

type WatcomExe struct {
	CodeBase uint32
	Code     []byte

	DataBase uint32
	Data     []byte

	BssBase   uint32
	BssLength uint32
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

	imageBase := binary.LittleEndian.Uint32(d[0xb4:][:4])

	codeBase := imageBase + binary.LittleEndian.Uint32(d[0x184:][:4])
	codeOffset := binary.LittleEndian.Uint32(d[0x18c:][:4])
	codeSize := binary.LittleEndian.Uint32(d[0x188:][:4])

	dataBase := imageBase + binary.LittleEndian.Uint32(d[0x1ac:][:4])
	dataOffset := binary.LittleEndian.Uint32(d[0x1b4:][:4])
	dataSize := binary.LittleEndian.Uint32(d[0x1b0:][:4])

	bssBase := imageBase + binary.LittleEndian.Uint32(d[0x1d4:][:4])
	// Note that Watcom exes incorrectly list bss size in the raw data size field
	// instead of virtual size field
	bssSize := binary.LittleEndian.Uint32(d[0x1d8:][:4])

	exe.CodeBase = codeBase
	exe.Code = make([]byte, codeSize, codeSize)
	copy(exe.Code, d[codeOffset:])

	exe.DataBase = dataBase
	exe.Data = make([]byte, dataSize, dataSize)
	copy(exe.Data, d[dataOffset:])

	exe.BssBase = bssBase
	exe.BssLength = bssSize

	return exe, nil
}

func main() {
	if true {
        f, err := os.Create("omfmatch.pprof")
        check(err)

        pprof.StartCPUProfile(f)
        defer pprof.StopCPUProfile()
    }

	if len(os.Args) < 3 {
		fmt.Printf("Usage: omfmatch target.exe [list of omf libs]\n")
		os.Exit(1)
	}

	objects := []*omf.Object{}
	for _, path := range os.Args[2:] {
		data := loadBinary(path)
		obj, err := omf.Parse(data)
		check(err)

		objects = append(objects, obj...)
	}
	fmt.Printf("%d objects parsed\n", len(objects))

	// Collect all available exports
	exports := map[string]string{}
	exportOffsets := map[string]uint32{}
	for _, object := range objects {
		for location := omf.Location(0); location < omf.LocationCount; location++ {
			for _, segment := range object.Segments[location] {
				for export, offset := range segment.Exports {
					if objectName, found := exports[export]; found {
						fmt.Printf("Export collision: %s:%s:%s:%q is already defined in %s\n", object.Name, location, segment.Name, export, objectName)
					} else {
						exports[export] = fmt.Sprintf("%q:%s:%q", object.Name, location, segment.Name)
						exportOffsets[export] = offset
					}
				}
			}
		}
	}

	// Check for missing imports
	missingImports := map[string]struct{}{}
	for _, object := range objects {
		for location := omf.Location(0); location < omf.LocationCount; location++ {
			for _, segment := range object.Segments[location] {
				for _, reloc := range segment.Relocs {
					rel, ok := reloc.(*omf.GlobalRelocation)
					if !ok {
						continue
					}

					if _, found := exports[rel.GlobalName]; !found {
						missingImports[rel.GlobalName] = struct{}{}
					}
				}
			}
		}
	}
	fmt.Printf("%d imports missing\n", len(missingImports))

	// Load the exe
	exe, err := LoadWatcomExe(os.Args[1])
	check(err)
	fmt.Printf("CODE: %08x: %d KiB\n", exe.CodeBase, len(exe.Code) / 1024)
	fmt.Printf("DATA: %08x: %d KiB\n", exe.DataBase, len(exe.Data) / 1024)
	fmt.Printf(" BSS: %08x: %d KiB\n", exe.BssBase, exe.BssLength / 1024)

	matchIndividual(
		objects,
		map[omf.Location][]byte{
			omf.LocationText: exe.Code,
			omf.LocationData: exe.Data,
			omf.LocationConst: exe.Data,
			omf.LocationStatic: make([]byte, exe.BssLength),
			omf.LocationStack: nil,
		},
		map[omf.Location]uint32{
			omf.LocationText: exe.CodeBase,
			omf.LocationData: exe.DataBase,
			omf.LocationConst: exe.DataBase,
			omf.LocationStatic: exe.BssBase,
			omf.LocationStack: 0,
		},
	)
}

func loadBinary(path string) []byte {
	f, err := os.Open(path)
	check(err)
	defer f.Close()
	d, err := io.ReadAll(f)
	check(err)
	return d
}

func check(err error) {
	if err != nil {
		panic(err)
	}
}

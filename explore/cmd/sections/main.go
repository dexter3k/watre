package main

import (
	"fmt"
	"os"
	"encoding/binary"
	"bytes"

	"github.com/dexter3k/watre/explore/ext/exe"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Printf("Usage: sections program.exe\n")
		os.Exit(1)
	}

	f, err := os.Open(os.Args[1])
	check(err)
	defer f.Close()

	file, err := exe.Read(f)
	check(err)

	for _, entry := range file.Sections {
		fmt.Printf("%8s: %08x+%6x -> %08x+%6x\n",
			entry.Name,
			entry.RawOffset, entry.RawSize,
			entry.VirtualAddress, entry.VirtualSize,
		)
	}

	if false {
		/* We should probably be pointing to .idata from IMAGE_IMPORT_DESCRIPTOR or similar */
		idata := file.GetSection(".idata")
		if idata == nil {
			panic("Missing import section?")
		}
		exts := parseIdataSection(idata)
		fmt.Printf("%v\n", exts)
	}

	if true {
		reloc := file.GetSection(".reloc")
		if reloc == nil {
			panic("Missing reloc section?")
		}

		fmt.Printf("%02x\n", reloc.Raw)
	}

	if false {
		printDwarfDebugInfo(file)
	}
}

type ExternalImport struct {
	Assembly string
	Label    string
}

func parseIdataSection(idata *exe.SectionEntry) map[uint32]ExternalImport {
	exts := map[uint32]ExternalImport{}

	r := bytes.NewBuffer(idata.Raw)
	type imageImportDescriptor struct {
		OriginalFirstThunk uint32
		TimeDateStamp      uint32
		ForwarderChain     uint32
		Name               uint32
		FirstThunk         uint32
	}

	cstr := func(data []byte) string {
		if idx := bytes.IndexByte(data, 0); idx != -1 {
			return string(data[:idx])
		}
		return string(data)
	}

	var zeroStruct imageImportDescriptor
	for {
		var tmp imageImportDescriptor
		if err := binary.Read(r, binary.LittleEndian, &tmp); err != nil {
			panic(err)
		}
		if tmp == zeroStruct {
			break
		}

		// All three must be within range of the idata
		tmp.OriginalFirstThunk -= idata.VirtualAddress
		tmp.Name -= idata.VirtualAddress
		tmp.FirstThunk -= idata.VirtualAddress

		if tmp.OriginalFirstThunk >= uint32(len(idata.Raw)) || tmp.Name >= uint32(len(idata.Raw)) || tmp.FirstThunk >= uint32(len(idata.Raw)) {
			panic(fmt.Errorf("Idata record is out of bounds"))
		}
		name := cstr(idata.Raw[tmp.Name:])

		count := 0
		for {
			src := binary.LittleEndian.Uint32(idata.Raw[tmp.OriginalFirstThunk:][count * 4:][:4])
			dst := binary.LittleEndian.Uint32(idata.Raw[tmp.FirstThunk:][count * 4:][:4])
			count++

			if src == 0 || dst == 0 {
				break
			}

			exts[dst] = ExternalImport{
				Assembly: name,
				Label:    cstr(idata.Raw[src - idata.VirtualAddress + 2:]),
			}
		}
	}

	return exts
}

func printDwarfDebugInfo(file *exe.File) {
	if file.Dwarf != nil {
		indent := ""
		r := file.Dwarf.Reader()
		for {
			entry, err := r.Next()
			check(err)
			if entry == nil {
				break
			}

			if entry.Tag == 0 {
				indent = indent[:max(0, len(indent)-2)]
				// continue
			}

			fmt.Printf("%s%v\n", indent, entry)

			if entry.Children {
				indent += "  "
			}
		}
	}
}

func check(err error) {
	if err != nil {
		panic(err)
	}
}

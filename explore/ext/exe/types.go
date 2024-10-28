package exe

import (
	"debug/dwarf"
)

type DosHeader struct {
	Magic          uint16
	Unparsed       [64 - 2 - 4]byte
	PeHeaderOffset uint32
}

type PeHeader struct {
	Magic    uint32
	Machine  uint16
	Sections uint16

	Unparsed [4 + 4 + 4]byte

	OptionalHeaderSize uint16
	Characteristics    uint16
}

type PeStandardFields struct {
	Magic       uint16
	LinkerMajor uint8
	LinkerMinor uint8

	SizeOfCode   uint32
	SizeOfInit   uint32
	SizeOfUninit uint32

	EntryPoints uint32
	BaseOfCode  uint32
	BaseOfData  uint32
}

type PeWindowsFields struct {
	ImageBase    uint32
	SectionAlign uint32
	FileAlign    uint32

	WindowsMajor   uint16
	WindowsMinor   uint16
	ImageMajor     uint16
	ImageMinor     uint16
	SubSystemMajor uint16
	SubSystemMinor uint16

	Zero uint32

	SizeOfImage   uint32
	SizeOfHeaders uint32
	CheckSum      uint32

	SubSystem uint16

	DllCharacteristics uint16

	SizeOfStackReserve uint32
	SizeOfStackCommit  uint32
	SizeOfHeapReserve  uint32
	SizeOfHeapCommit   uint32

	LoaderFlags    uint32
	DataDirEntries uint32
}

type SectionEntry struct {
	Name string

	VirtualSize    uint32
	VirtualAddress uint32
	RawSize        uint32
	RawOffset      uint32
	Raw            []byte

	Unparsed [4 + 4 + 2 + 2 + 4]byte
}

type File struct {
	Dos      DosHeader
	Pe       PeHeader
	Standard PeStandardFields
	Windows  PeWindowsFields
	Sections []SectionEntry
	Dwarf    *dwarf.Data
}

func (f *File) GetSection(name string) *SectionEntry {
	for i, entry := range f.Sections {
		if entry.Name != name {
			continue
		}

		return &f.Sections[i]
	}

	return nil
}

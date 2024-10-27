package exe

import (
	"io"
	"encoding/binary"
	"fmt"
	"bytes"
	"debug/elf"
)

func Read(f io.ReadSeeker) (*File, error) {
	var dosHeader DosHeader
	if err := binary.Read(f, binary.LittleEndian, &dosHeader); err != nil {
		return nil, err
	}
	if dosHeader.Magic != 0x5a4d {
		return nil, fmt.Errorf("Invalid DOS Header Magic: %04x", dosHeader.Magic)
	}
	if _, err := f.Seek(int64(dosHeader.PeHeaderOffset) - 64, 1); err != nil {
		return nil, err
	}

	var peHeader PeHeader
	if err := binary.Read(f, binary.LittleEndian, &peHeader); err != nil {
		return nil, err
	}
	if peHeader.Magic != 0x4550 {
		return nil, fmt.Errorf("Invalid PE Header Magic: %08x", peHeader.Magic)
	}
	if peHeader.Machine != 0x14c {
		return nil, fmt.Errorf("Unknown PE Machine: %04x", peHeader.Machine)
	}
	if peHeader.OptionalHeaderSize < 96 {
		return nil, fmt.Errorf("Unknown PE Extra Header size: %d", peHeader.OptionalHeaderSize)
	}
	dataDirCountFromSize := (peHeader.OptionalHeaderSize - 96) / 8
	if peHeader.OptionalHeaderSize - 96 != dataDirCountFromSize * 8 {
		return nil, fmt.Errorf("Misaligned PE data dir sizes: %d (mod)", (peHeader.OptionalHeaderSize - 96) % 8)
	}

	var standardFields PeStandardFields
	if err := binary.Read(f, binary.LittleEndian, &standardFields); err != nil {
		return nil, err
	}
	if standardFields.Magic != 0x10b {
		return nil, fmt.Errorf("Invalid PE Standard Header Magic: %04x", standardFields.Magic)
	}

	var windowsFields PeWindowsFields
	if err := binary.Read(f, binary.LittleEndian, &windowsFields); err != nil {
		return nil, err
	}
	if windowsFields.DataDirEntries != uint32(dataDirCountFromSize) {
		return nil, fmt.Errorf("Provided data dir count is not equal to calculated: %d vs %d", windowsFields.DataDirEntries, dataDirCountFromSize)
	}

	if _, err := f.Seek(int64(windowsFields.DataDirEntries) * 8, 1); err != nil {
		return nil, err
	}

	var sections []SectionEntry
	for i := 0; i < int(peHeader.Sections); i++ {
		var buf[8]byte
		if err := binary.Read(f, binary.LittleEndian, buf[:]); err != nil {
			return nil, err
		}

		idx := bytes.IndexByte(buf[:], 0)
		if idx == -1 {
			idx = len(buf)
		}

		entry := SectionEntry{
			Name: string(buf[:idx]),
		}

		if err := binary.Read(f, binary.LittleEndian, &entry.VirtualSize); err != nil {
			return nil, err
		}
		if err := binary.Read(f, binary.LittleEndian, &entry.VirtualAddress); err != nil {
			return nil, err
		}
		if err := binary.Read(f, binary.LittleEndian, &entry.RawSize); err != nil {
			return nil, err
		}
		if err := binary.Read(f, binary.LittleEndian, &entry.RawOffset); err != nil {
			return nil, err
		}
		if err := binary.Read(f, binary.LittleEndian, entry.Unparsed[:]); err != nil {
			return nil, err
		}

		entry.VirtualSize = max(entry.VirtualSize, entry.RawSize)
		if entry.RawOffset == 0 || entry.RawSize == 0 {
			entry.RawOffset = 0
			entry.RawSize = 0
		}

		sections = append(sections, entry)
	}

	var offsetAfterSections int64

	for i, entry := range sections {
		if entry.RawSize > 0 {
			offsetAfterSections = max(offsetAfterSections, int64(entry.RawOffset) + int64(entry.RawSize))

			if _, err := f.Seek(int64(entry.RawOffset), 0); err != nil {
				return nil, err
			}

			data := make([]byte, entry.RawSize)
			if err := binary.Read(f, binary.LittleEndian, data); err != nil {
				return nil, err
			}

			sections[i].Raw = data
		}
	}

	// Find out if there is anything past the section data
	if _, err := f.Seek(offsetAfterSections, 0); err != nil {
		return nil, err
	}

	data, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}

	file := File{
		Dos:      dosHeader,
		Pe:       peHeader,
		Standard: standardFields,
		Windows:  windowsFields,
		Sections: sections,
	}

	if len(data) > 0 {
		elfFile, err := elf.NewFile(bytes.NewReader(data))
		if err != nil {
			return nil, err
		}

		dbg, err := elfFile.DWARF()
		if err != nil {
			return nil, err
		}

		file.Dwarf = dbg
	}

	return &file, nil
}

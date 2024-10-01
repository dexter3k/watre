package main

import (
	"os"
	"io"
	"fmt"
	"encoding/binary"

	// "github.com/dexter3k/watre/explore/ext/omf"
)

func parseOmfObject(data []byte) (int, error) {
	le := binary.LittleEndian

	loadIndex := func(data []byte) (uint16, []byte) {
		if (data[0] & 0x80) != 0 {
			return (uint16(data[0] & 0x7f) << 8) | uint16(data[1]), data[2:]
		} else {
			return uint16(data[0]), data[1:]
		}
	}

	i := 0
tagLoop:
	for {
		tag := data[i + 0]
		size := int(le.Uint16(data[i + 1:][:2]))

		chk := data[i + size + 2]
		if chk != 0 {
			var sum uint8
			for _, v := range data[i:][:size + 3] {
				sum += v
			}
			if sum != 0 {
				return i, fmt.Errorf("checksum failed")
			}
		}

		content := data[i + 3:][:size - 1]
		i += size + 3

		switch tag {
		case 0x80: // OMF Object Start
			objName := string(content[1:][:content[0]])
			content = content[1 + content[0]:]

			fmt.Printf("\nOMF Object %q\n", objName)
		case 0x8a: // OMF Object End
			break tagLoop
		case 0x96: // OMF_LNAMES
			fmt.Printf("\tOMF_LNAMES\n")

			index := 0
			for len(content) > 0 {
				name := string(content[1:][:content[0]])
				content = content[1 + content[0]:]

				fmt.Printf("\t\t%d: %q\n", index, name)
				index += 1
			}
		case 0x99: // CMD_SEGDEF32
			segmentAttributes := content[0]
			segmentSize := le.Uint32(content[1:][:4])
			content = content[5:]

			var segmentName, segmentSection, segmentOverlay uint16
			segmentName, content = loadIndex(content)
			segmentSection, content = loadIndex(content)
			segmentOverlay, content = loadIndex(content)

			segmentName -= 1
			segmentSection -= 1

			fmt.Printf("\tCMD_SEGDEF32\n")
			fmt.Printf("\t\tattributes = %02x\n", segmentAttributes)
			fmt.Printf("\t\t      size = %d\n", segmentSize)
			fmt.Printf("\t\t      name = %d\n", segmentName)
			fmt.Printf("\t\t   section = %d\n", segmentSection)
			fmt.Printf("\t\t   overlay = %d\n", segmentOverlay) // 1
		case 0x9a: // CMD_GRPDEF
			groupIndex := content[0]
			groupFF := content[1]
			content = content[2:]

			var groupSegment uint16
			groupSegment, content = loadIndex(content)
			groupSegment -= 1

			fmt.Printf("\tCMD_GRPDEF\n")
			fmt.Printf("\t\t  index = %d\n", groupIndex)
			fmt.Printf("\t\t   0xff = %02x\n", groupFF)
			fmt.Printf("\t\tsegment = %d\n", groupSegment)
		case 0x8c, 0xb4: // CMD_EXTDEF, CMD_LEXTDEF
			importsLocal := tag == 0xb4
			fmt.Printf("\tCMD_EXTDEF local=%v\n", importsLocal)

			index := 0
			for len(content) > 0 {
				importName := string(content[1:][:content[0]])
				content = content[1 + content[0]:]

				fmt.Printf("\t\t%d: %q\n", index, importName)
				index += 1
			}
		case 0x90, 0x91, 0xb6, 0xb7: // CMD_PUBDEF, CMD_PUBDEF32, CMD_LPUBDEF, CMD_LPUBDEF32
			exportsLocal := (tag & 0xfe) == 0xb6
			exports32 := (tag & 1) != 0

			var exportsGroup, exportsSegment uint16
			exportsGroup, content = loadIndex(content)
			exportsSegment, content = loadIndex(content)

			exportsSegment -= 1

			fmt.Printf("\tCMD_PUBDEF local=%v 32=%v\n", exportsLocal, exports32)
			fmt.Printf("\t\t  group = %d\n", exportsGroup)
			fmt.Printf("\t\tsegment = %d\n", exportsSegment)

			index := 0
			for len(content) > 0 {
				exportName := string(content[1:][:content[0]])
				content = content[1 + content[0]:]

				var exportOffset uint32
				if exports32 {
					exportOffset = le.Uint32(content[:4])
					content = content[4:]
				} else {
					exportOffset = uint32(le.Uint16(content[:2]))
					content = content[2:]
				}

				var exportType uint16
				exportType, content = loadIndex(content)

				fmt.Printf("\t\t\t%d\n", index)
				index += 1

				fmt.Printf("\t\t\t\t  name = %q\n", exportName)
				fmt.Printf("\t\t\t\toffset = %08x\n", exportOffset)
				fmt.Printf("\t\t\t\t  type = %d\n", exportType) // always zero
			}
		case 0x88: // Linker comment
			fmt.Printf("\tLINKER_COMMENT\n")
			fmt.Printf("\t\t%02x\n", content)
			content = content[len(content):]
		case 0xa0, 0xa1: // CMD_LEDATA, CMD_LEDATA32
			ledata32 := (tag & 1) != 0

			var ledataSegment uint16
			ledataSegment, content = loadIndex(content)

			ledataSegment -= 1

			var ledataOffset uint32
			if ledata32 {
				ledataOffset = le.Uint32(content[:4])
				content = content[4:]
			} else {
				ledataOffset = uint32(le.Uint16(content[:2]))
				content = content[2:]
			}

			fmt.Printf("\tCMD_LEDATA 32=%v\n", ledata32)
			fmt.Printf("\t\tsegment = %d\n", ledataSegment)
			fmt.Printf("\t\t offset = %08x\n", ledataOffset)
			fmt.Printf("\t\t   data = %02x\n", content)
			content = content[len(content):]
		case 0x9d: // CMD_FIXUPP32
			fmt.Printf("\tCMD_FIXUPP32\n")

			index := 0
			for len(content) > 0 {
				fmt.Printf("\t\t%d\n", index)
				index += 1

				fixupCursor0 := content[0]
				fixupCursor1 := content[1]
				fixupCursor2 := content[2]
				content = content[3:]

				fixupLocation := fixupCursor0 >> 6
				fixupClass := (fixupCursor0 >> 2) & 0xf
				fixupOffset := (uint16(fixupCursor0 & 3) << 8) + uint16(fixupCursor1)

				fixupFrame := fixupCursor2 >> 4
				fixupTarget := fixupCursor2 & 3

				fmt.Printf("\t\t\tlocation = %d (%s)\n", fixupLocation, []string{
					"unknown", "unknown", "relative", "absolute",
				}[fixupLocation])
				fmt.Printf("\t\t\t   class = %d (%s)\n", fixupClass, []string{
					"lobyte", "offset", "base", "ptr",
					"hibyte", "ldr offset", "phar ptr", "unknown",
					"unknown", "ms offset 32", "unknown", "ms ptr",
					"unknown", "ms ldr offset 32", "unknown", "unknown",
				}[fixupClass])
				fmt.Printf("\t\t\t  offset = %d\n", fixupOffset)
				fmt.Printf("\t\t\t   frame = %d (%s)\n", fixupFrame, []string{
					"segment index", "group index", "external index", "absolute frame number",
					"with location", "same as target", "no frame", "unknown",
					"unknown", "unknown", "unknown", "unknown",
					"unknown", "unknown", "unknown", "unknown",
				}[fixupFrame])
				fmt.Printf("\t\t\t  target = %d (%s)\n", fixupTarget, []string{
					"segment", "group", "implied", "absolute",
				}[fixupTarget])

				if fixupLocation == 0 || fixupLocation == 1 {
					panic(fmt.Errorf("Unsupported fixup location: %d", fixupLocation))
				}
				if fixupClass != 9 {
					panic(fmt.Errorf("Unsupported fixup class: %d", fixupClass))
				}
				if fixupFrame != 5 && fixupFrame != 1 {
					panic(fmt.Errorf("Unsupported fixup frame: %d\n", fixupFrame))
				}
				if fixupTarget == 3 {
					panic(fmt.Errorf("Unsupported fixup target: %d\n", fixupTarget))
				}

				if fixupFrame == 1 {
					var frameValue uint16
					frameValue, content = loadIndex(content)
					fmt.Printf("\t\t\t f_value = %d\n", frameValue)
				}

				var targetValue uint16
				targetValue, content = loadIndex(content)
				fmt.Printf("\t\t\t t_value = %d\n", targetValue)
			}
		default:
			fmt.Printf("%02x\n", content)
			return i, fmt.Errorf("unknown omf object tag: %02x\n", tag)
		}

		if len(content) != 0 {
			fmt.Printf("\tcontent_extra = %02x\n", content)
		}
	}

	return i, nil
}

func main() {
	if len(os.Args) < 2 {
		fmt.Printf("Usage: omfdump file.lib\n")
		return
	}

	data := loadBinary(os.Args[1])
	if data[0] != 0xf0 {
		panic(fmt.Errorf("Invalid header: %02x", data[:2]))
	}
	if data[1] == 0x01 {
		panic(fmt.Errorf("Invalid header: %02x", data[:2]))
	}

	le := binary.LittleEndian
	omfPageSize := le.Uint16(data[1:][:2]) + 3
	omfDictOffset := le.Uint32(data[3:][:4])
	omfDictSize := le.Uint16(data[7:][:2])
	omfFlags := data[9]

	fmt.Printf("OMF:\n")
	fmt.Printf("\t  page_size = %d\n", omfPageSize)
	fmt.Printf("\tdict_offset = %d\n", omfDictOffset)
	fmt.Printf("\t  dict_size = %d\n", omfDictSize)
	fmt.Printf("\t      flags = %02x\n", omfFlags)

	if omfPageSize < 10 {
		panic(fmt.Errorf("Page size won't fit even the header"))
	} else if (omfPageSize & (omfPageSize - 1)) != 0 {
		panic(fmt.Errorf("Page size is supposed to be a power of two"))
	}

	pageSizeMask := int(omfPageSize) - 1

	i := 1 * int(omfPageSize)
	for data[i] != 0xf1 {
		length, err := parseOmfObject(data[i:])
		check(err)

		i += length
		i_aligned_up := (i + pageSizeMask) & ^pageSizeMask
		i = i_aligned_up
	}
}

func loadBinary(path string) []byte {
	f, err := os.Open(path)
	check(err)
	d, err := io.ReadAll(f)
	f.Close()
	check(err)
	return d
}

func check(err error) {
	if err != nil {
		panic(err)
	}
}

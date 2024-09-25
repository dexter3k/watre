package main

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
)

type Matcher struct {
	target []byte

	omfLibs []*OmfLibrary
}

func NewMatcher(target []byte) Matcher {
	return Matcher{
		target: target,
	}
}

func (m *Matcher) CheckLibDirectory(dir string) error {

	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return fmt.Errorf("checking lib directory: %w", err)
		}

		if d.IsDir() {
			if filepath.Clean(path) != filepath.Clean(dir) {
				return fs.SkipDir
			}
			return nil
		}

		ext := filepath.Ext(d.Name())
		if ext != ".obj" && ext != ".lib" {
			return nil
		}
		return m.CheckLibOrObjFile(path)
	})

	return err
}

func (m *Matcher) CheckLibOrObjFile(path string) error {
	data := loadBinary(path)
	if data[0] == 0xf0 && data[1] == 0x01 {
		return fmt.Errorf("Unsupported library format")
	} else if data[0] == 0xf0 {
		return m.CheckOMF(path, data)
	} else if string(data[0:8]) == "!<arch>\n" {
		return m.CheckAR(path, data)
	} else if data[0] == 0x4c && data[1] == 0x01 {
		return m.CheckCOFF(path, data)
	} else {
		return fmt.Errorf("Invalid file format")
	}
	return nil
}

func (m *Matcher) CheckOMF(path string, data []byte) error {
	omf, err := ParseOmfLibrary(path, data)
	if err != nil {
		return err
	}
	m.omfLibs = append(m.omfLibs, &omf)

	return nil
}

func (m *Matcher) CheckAR(path string, data []byte) error {
	return nil
}

func (m *Matcher) CheckCOFF(path string, data []byte) error {
	return nil
}

func main() {
	// Run with two+ params: target.exe [a list of all lib directories]
	// Prints JSON with information on where which lib was found
	if len(os.Args) < 3 {
		fmt.Printf("Usage: libmatch target.exe [list of lib dirs]")
		os.Exit(1)
	}

	target := loadBinary(os.Args[1])
	matcher := NewMatcher(target)

	for _, path := range os.Args[2:] {
		info, err := os.Stat(path)
		check(err)

		if info.IsDir() {
			check(matcher.CheckLibDirectory(path))
		} else {
			check(fmt.Errorf("Specifying files as libs/obj is not implemented"))
		}
	}

	objects := 0
	for _, lib := range matcher.omfLibs {
		objects += len(lib.Objects)
	}

	// fmt.Printf("%d OMF libs, %d objects loaded\n", len(matcher.omfLibs), objects)

	exe, err := LoadWatcomExe(os.Args[1])
	check(err)

	fmt.Printf("%02x\n", exe.Code[:32])

	excludeLibs := map[string]struct{}{
		"C:\\WATCOM_10_6\\lib386\\math387s.lib":     struct{}{},
		"C:\\WATCOM_10_6\\lib386\\math3r.lib":       struct{}{},
		"C:\\WATCOM_10_6\\lib386\\math3s.lib":       struct{}{},
		"C:\\WATCOM_10_6\\lib386\\nt\\clib3s.lib":   struct{}{},
		"C:\\WATCOM_10_6\\lib386\\nt\\pfsn3r.lib":   struct{}{},
		"C:\\WATCOM_10_6\\lib386\\nt\\pfsnmt3r.lib": struct{}{},
		"C:\\WATCOM_10_6\\lib386\\nt\\pfsx3r.lib":   struct{}{},
		"C:\\WATCOM_10_6\\lib386\\nt\\pfsxmt3r.lib": struct{}{},
		"C:\\WATCOM_10_6\\lib386\\plbx3r.lib":       struct{}{},
		"C:\\WATCOM_10_6\\lib386\\plbxmt3r.lib":     struct{}{},
		"C:\\WATCOM_10_6\\lib386\\plib3r.lib":       struct{}{},
		"C:\\WATCOM_10_6\\lib386\\plibmt3r.lib":     struct{}{},
	}

	foundMatches := map[uint32]uint32{}

	for _, lib := range matcher.omfLibs {
		if _, found := excludeLibs[lib.Path]; found {
			continue
		}

		for _, obj := range lib.Objects {
			for _, seg := range obj.Segments {
				if seg.Section != "CODE" || len(seg.Data) - len(seg.Fixups) * 4 < 9 {
					continue
				}

codeLinearSearch:
				for i := 0; i < len(exe.Code); i++ {
					fixupPtr := 0

					for j := 0; j < len(seg.Data); j++ {
						if i + j >= len(exe.Code) {
							continue codeLinearSearch
						}

						if fixupPtr < len(seg.Fixups) && uint32(j) >= seg.Fixups[fixupPtr].Offset {
							if uint32(j) == seg.Fixups[fixupPtr].Offset {
								// We're walking over a fixup
								j += 3
								fixupPtr += 1
								continue
							} else if uint32(j) < seg.Fixups[fixupPtr].Offset + 4 {
								fmt.Printf("%d %d %d %d\n", j, fixupPtr, seg.Fixups[fixupPtr - 1].Offset, seg.Fixups[fixupPtr].Offset)
								panic("o no panik!")
							} else if uint32(j) >= seg.Fixups[fixupPtr].Offset + 4 {
								fixupPtr += 1
							}
						}

						if exe.Code[i + j] != seg.Data[j] {
							continue codeLinearSearch
						}
					}

					// We matched! Try finding related export
					fmt.Printf("0x%06x-0x%06x: %q %q\n", exe.CodeBase + uint32(i), exe.CodeBase + uint32(i) + uint32(len(seg.Data)), lib.Path, obj.Name)
					if _, found := foundMatches[uint32(i)]; found {
						foundMatches[uint32(i)] = max(foundMatches[uint32(i)], uint32(len(seg.Data)))
					}
					foundMatches[uint32(i)] = uint32(len(seg.Data))
					// fmt.Printf("%02x\n", seg.Data)
				}
			}
		}
	}

	sortedMatches := []uint32{}
	for k, _ := range foundMatches {
		sortedMatches = append(sortedMatches, k)
	}
	slices.Sort(sortedMatches)

	chunk := []byte{}
	chunkBase := uint32(0x10)

	for pc := uint32(0x10); pc < uint32(len(exe.Code)); pc++ {
		if len(sortedMatches) > 0 && sortedMatches[0] == pc {
			if len(chunk) > 0 {
				fmt.Printf("%08x-%08x: %02x\n", chunkBase + exe.CodeBase, chunkBase + exe.CodeBase + uint32(len(chunk)), chunk)
			}

			skipTo := sortedMatches[0] + foundMatches[sortedMatches[0]]
			for pc < skipTo {
				for len(sortedMatches) > 0 && sortedMatches[0] <= skipTo {
					skipTo = max(skipTo, sortedMatches[0] + foundMatches[sortedMatches[0]])
					fmt.Printf("Skipping %08x -> %08x\n", sortedMatches[0] + exe.CodeBase, skipTo + exe.CodeBase)
					sortedMatches = sortedMatches[1:]
				}
				pc++
			}

			chunk = chunk[:0]
			chunkBase = pc
		}

		chunk = append(chunk, exe.Code[pc])
	}

	if len(chunk) > 0 {
		fmt.Printf("%08x-%08x: %02x\n", chunkBase + exe.CodeBase, chunkBase + exe.CodeBase + uint32(len(chunk)), chunk)
	}
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

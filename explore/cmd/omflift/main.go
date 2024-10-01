package main

import (
	"os"
	"io"
	"fmt"
	"strings"
	"slices"

	"github.com/dexter3k/watre/explore/ext/omf"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Printf("Usage: omfdump file.lib\n")
		return
	}

	data := loadBinary(os.Args[1])
	objects, err := omf.Parse(data)
	check(err)

	for _, object := range objects {
		fmt.Printf("OMF Object %q:\n", object.Name)
		for location := omf.Location(0); location < omf.LocationCount; location++ {
			for _, segment := range object.Segments[location] {
				fmt.Printf("\t%s:%q\n", location, segment.Name)

				if len(segment.Data) > 0 {
					fmt.Printf("\t\tData:\n")
					fmt.Printf("\t\t\t%02x\n", segment.Data)
				}

				if len(segment.Relocs) > 0 {
					fmt.Printf("\t\tRelocs:\n")
					keys := make([]uint32, 0, len(segment.Relocs))
					for key := range segment.Relocs {
						keys = append(keys, key)
					}
					slices.Sort(keys)
					for _, offset := range keys {
						switch reloc := segment.Relocs[offset].(type) {
						case *omf.LocalRelocation:
							fmt.Printf("\t\t\t%08x: %s -> %s\n", offset, reloc.Type, reloc.LocalRef)
						case *omf.GlobalRelocation:
							fmt.Printf("\t\t\t%08x: %s -> %s:%08x\n", offset, reloc.Type, reloc.GlobalName, reloc.Offset)
						default:
							panic(fmt.Errorf("%T", reloc))
						}
					}
				}

				if len(segment.Exports) > 0 {
					fmt.Printf("\t\tExports:\n")
					keys := make([]string, 0, len(segment.Exports))
					for key := range segment.Exports {
						keys = append(keys, key)
					}
					slices.SortFunc(keys, func(a, b string) int {
						if segment.Exports[a] == segment.Exports[b] {
							return strings.Compare(a, b)
						}
						return int(segment.Exports[a]) - int(segment.Exports[b])
					})
					for _, name := range keys {
						fmt.Printf("\t\t\t%08x: %q\n", segment.Exports[name], name)
					}
				}
			}
		}
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

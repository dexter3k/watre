package main

import (
	"fmt"
	"os"

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

	printDwarfDebugInfo(file)
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

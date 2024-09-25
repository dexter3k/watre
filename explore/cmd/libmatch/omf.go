package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"errors"
)

var (
	ErrSkipParsing = fmt.Errorf("skipping this object")
	ErrFeatureNotImplemented = fmt.Errorf("feature is not implemented: %w", ErrSkipParsing)
	ErrPharLapFormat = fmt.Errorf("PharLap OMF encountered: %w", ErrFeatureNotImplemented)
)

type OmfLibrary struct {
	Path    string
	Objects []*OmfObject
	Exports map[string]*OmfObject
}

type omfLibHeader struct {
	signature  uint8
	pageSize   uint16
	dictOffset uint32
	dictSize   uint16
	flags      uint8
}

func ParseOmfLibrary(path string, data []byte) (OmfLibrary, error) {
	lib := OmfLibrary{
		Path:    path,
		Exports: map[string]*OmfObject{},
	}

	header := omfLibHeader{
		signature: data[0],
		pageSize: binary.LittleEndian.Uint16(data[1:][:2]) + 3,
		dictOffset: binary.LittleEndian.Uint32(data[3:][:4]),
		dictSize: binary.LittleEndian.Uint16(data[7:][:2]),
		flags: data[9],
	}
	if header.signature != 0xf0 {
		return lib, fmt.Errorf("unknown omf library signature: %02x", header.signature)
	}

	i := int(header.pageSize)
	for i < int(header.dictOffset) - 1 && data[i] != 0xf1 {
		obj, length, err := ParseOmfObject(data[i:])
		if err != nil && !errors.Is(err, ErrSkipParsing) {
			return lib, err
		}

		i += length
		i = (i + int(header.pageSize - 1)) & ^int(header.pageSize - 1)

		if errors.Is(err, ErrSkipParsing) {
			continue
		}

		lib.Objects = append(lib.Objects, &obj)
		for name, export := range obj.Exports {
			if export.Local {
				continue
			}

			if _, found := lib.Exports[name]; found {
				panic(fmt.Errorf("Export symbol collision"))
			}

			lib.Exports[name] = lib.Objects[len(lib.Objects) - 1]
		}
	}

	return lib, nil
}



type OmfObjectFixup struct {
	Offset   uint32
	Relative bool
	Segment  *OmfObjectSegment
	Label    string
	Local    bool
}

type OmfObjectSegment struct {
	Section string
	Size    uint32
	Data    []byte
	Fixups  []OmfObjectFixup
}

type OmfObjectExport struct {
	Segment *OmfObjectSegment
	Offset  uint32
	Local   bool
}

type OmfObject struct {
	Name     string
	Segments []*OmfObjectSegment
	Exports  map[string]OmfObjectExport
}



type omfObjectSegdef struct {
	name    string
	section string
	size    uint32
}

type omfObjectPubdef struct {
	segment uint16
	offset  uint32
	label   string
	local   bool
}

type omfObjectExtdef struct {
	label string
	local bool
}

type omfObjectFixup struct {
	offset   uint32
	kind     uint8  // 4 points to segment, 6 points to extdef
	index    uint16
	relative bool
}

type omfObjectBuilder struct {
	name      string

	lnames    []string

	segments []omfObjectSegdef

	ledatas           map[uint16][]byte
	lastLedataSegment uint16
	lastLedataOffset  uint32

	fixups map[uint16][]omfObjectFixup

	// All public/private symbols defined
	pubdefs []omfObjectPubdef
	extdefs []omfObjectExtdef
}

func loadIndex(data []byte) (uint16, []byte) {
	if (data[0] & 0x80) != 0 {
		return (uint16(data[0] & 0x7f) << 8) | uint16(data[1]), data[2:]
	} else {
		return uint16(data[0]), data[1:]
	}
}

func (b *omfObjectBuilder) setName(name string) {
	b.name = name
}

func (b *omfObjectBuilder) parseLnames(data []byte) {
	for len(data) > 0 {
		size := data[0]
		name := string(data[1:][:size])
		data = data[1+size:]
		b.lnames = append(b.lnames, name)
	}
}

func (b *omfObjectBuilder) parseSegdef32(data []byte) {
	// Section opts, we don't care, I think
	data = data[1:]

	// Size of the section
	size := binary.LittleEndian.Uint32(data[:4])
	data = data[4:]

	var name uint16
	name, data = loadIndex(data)

	var section uint16
	section, data = loadIndex(data)

	def := omfObjectSegdef{
		name:    b.lnames[name - 1],
		section: b.lnames[section - 1],
		size:    size,
	}

	b.segments = append(b.segments, def)
}

func (b *omfObjectBuilder) parseExtdef16(data []byte, local bool) {
	for len(data) > 0 {
		size := data[0]
		if size > 0 {
			name := string(data[1:][:size])
			b.extdefs = append(b.extdefs, omfObjectExtdef{
				label: name,
				local: local,
			})
		}
		data = data[1+size:]
	}
}

func (b *omfObjectBuilder) parseLedata(data []byte, is32 bool) {
	var segment uint16
	segment, data = loadIndex(data)

	var offset uint32
	if is32 {
		offset = binary.LittleEndian.Uint32(data[:4])
		data = data[4:]
	} else {
		offset = uint32(binary.LittleEndian.Uint16(data[:2]))
		data = data[2:]
	}

	space, found := b.ledatas[segment]
	if !found {
		space = []byte{}
	}

	if len(space) > int(offset) {
		if int(offset) + len(data) > len(space) {
			// Make sure we have enough space at the end
			space = append(space, make([]byte, int(offset) + len(data) - len(space))...)
		}
		copy(space[offset:], data)
	} else if len(space) < int(offset) {
		space = append(space, make([]byte, int(offset) - len(space))...)
		space = append(space, data...)
	} else {
		space = append(space, data...)
	}

	b.ledatas[segment] = space

	// This will be needed for fixups
	b.lastLedataSegment = segment
	b.lastLedataOffset = offset
}

func (b *omfObjectBuilder) parsePubdef(data []byte, local bool, is32 bool) error {
	// var group uint16
	_, data = loadIndex(data)

	var segment uint16
	segment, data = loadIndex(data)
	if segment == 0 {
		return fmt.Errorf("segment = 0 in pubdef: %w", ErrFeatureNotImplemented)
	}

	for len(data) > 0 {
		size := data[0]
		data = data[1:]

		name := string(data[:size])
		data = data[size:]

		var offset uint32
		if is32 {
			offset = binary.LittleEndian.Uint32(data[:4])
			data = data[4:]
		} else {
			offset = uint32(binary.LittleEndian.Uint16(data[:2]))
			data = data[2:]
		}

		// Unknown unused index
		_, data = loadIndex(data)

		b.pubdefs = append(b.pubdefs, omfObjectPubdef{
			segment: segment,
			offset:  offset,
			label:   name,
			local:   local,
		})
	}

	return nil
}

func (b *omfObjectBuilder) parseFixup32(data []byte) error {
	for len(data) > 0 {
		if ((data[0] & 0x80) == 0) {
			panic(fmt.Errorf("Threaded fixup is not supported/implemented"))
		}

		relative := (data[0] & 0x40) == 0
		style := ((data[0] >> 2) & 0xf)
		if (style != 9 && style != 11 && style != 0) {
			panic(fmt.Errorf("Only MS-styled fixups are supported, encountered %d", style))
		}
		if (style == 0 || style == 11) {
			return fmt.Errorf("only ms-styled 4-byte fixups are supported: %w", ErrFeatureNotImplemented)
		}
		offset := (uint32(data[0] & 3) << 8) | uint32(data[1])
		data = data[2:]

		// Now second part...
		if (data[0] & 0x80) != 0 {
			panic(fmt.Errorf("Threaded fixup is not supported/implemented"))
		}
		if (data[0] & 0x08) != 0 {
			panic(fmt.Errorf("Threaded fixup is not supported/implemented"))
		}
		if (data[0] & 0x04) == 0 {
			panic(fmt.Errorf("I don't even know what it is and where it is used"))
		}

		k := data[0]
		data = data[1:]


		fidx := uint16(0)
		fmethod := (k >> 4) & 0x07
		switch fmethod {
		case 1: // group index
			fidx, data = loadIndex(data)
		case 5: // same as target
		default:
			panic(fmethod)
		}

		tmethod := k & 0x07
		tidx := uint16(0)

		tidx, data = loadIndex(data)

		if fmethod == 5 {
			fmethod = tmethod & 0x03
			fidx = tidx
		}

		switch tmethod {
		case 4: // segment
		case 6: // external
		default:
			panic(fmt.Errorf("unknown tmethod: %d", tmethod))
		}

		// Ok, now, to be clear, I don't really care about frame specifier.
		// We know where the relocation is going to end up and we just need to know the target symbol name
		// We don't care about the actual value that is going to end up there.
		// So extract: segment+offset+type(4-byte), extracted symbol name, is it absolute or relative?

		// Now about types. There are three types that I have encountered:
		// -  9. This is the most basic 4-byte relocation
		// -  0. This is some random 1-byte relocation, now idea what this is useful for
		// - 11. 6-byte segment-based relocation. What the hell?

		fixups, found := b.fixups[b.lastLedataSegment]
		if !found {
			fixups = []omfObjectFixup{}
		}

		fixups = append(fixups, omfObjectFixup{
			offset:   b.lastLedataOffset + offset,
			kind:     tmethod,
			index:    tidx,
			relative: relative,
		})

		b.fixups[b.lastLedataSegment] = fixups

		if false {
			fmt.Printf("[%d] %d@%08x %d-%d %d-%d relative=%v\n", style, b.lastLedataSegment, offset + b.lastLedataOffset, fmethod, fidx, tmethod, tidx, relative)
		}
	}

	return nil
}

// type OmfObjectFixup struct {
// 	Offset   uint32
// 	Relative bool
// 	Segment  *OmfObjectSegment
// 	Label    string
// 	Local    bool
// }

// type OmfObjectSegment struct {
// 	Section string
// 	Size    uint32
// 	Data    []byte
// 	Fixups  []OmfObjectFixup
// }

// type OmfObjectExport struct {
// 	Segment *OmfObjectSegment
// 	Offset  uint32
//  Local   bool
// }

// type OmfObject struct {
// 	Name     string
// 	Segments []*OmfObjectSegment
// 	Exports  map[string]OmfObjectExport
// }

func (b *omfObjectBuilder) build() (OmfObject, error) {
	obj := OmfObject{
		Name:    b.name,
		Exports: map[string]OmfObjectExport{},
	}

	objSegmentRemap := map[int]*OmfObjectSegment{}
	for i, segment := range b.segments {
		if segment.size == 0 {
			continue
		}

		seg := &OmfObjectSegment{
			Section: segment.section,
			Size:    segment.size,
		}

		if data, found := b.ledatas[uint16(i + 1)]; found {
			seg.Data = data
		}

		objSegmentRemap[i] = seg
		obj.Segments = append(obj.Segments, seg)
	}

	// First locate all pubdefs to check presence of localdefs
	for _, def := range b.pubdefs {
		// Some public defs point to empty segments.
		// These are just empty labels with no data though
		seg, _ := objSegmentRemap[int(def.segment - 1)]

		obj.Exports[def.label] = OmfObjectExport{
			Segment: seg,
			Offset:  def.offset,
			Local:   def.local,
		}
	}

	for i, segment := range b.segments {
		if segment.size == 0 {
			continue
		}

		fixups, found := b.fixups[uint16(i + 1)]
		if !found {
			continue
		}

		for _, fixup := range fixups {
			if fixup.kind == 4 {
				seg, _ := objSegmentRemap[int(fixup.index - 1)]
				if seg == nil {
					// How do we map empty segments then? What value do they receive?
					// panic(fmt.Errorf("Can't have pointer to empty/unknown segment!"))
				}

				objSegmentRemap[i].Fixups = append(objSegmentRemap[i].Fixups, OmfObjectFixup{
					Offset:   fixup.offset,
					Relative: fixup.relative,
					Segment:  seg,
				})
			} else if fixup.kind == 6 {
				ext := b.extdefs[fixup.index - 1]

				if ext.local {
					// Ensure we have defined this pubdef
					if export, found := obj.Exports[ext.label]; !found {
						panic(fmt.Errorf("can't reference non-existent local var"))
					} else if !export.Local {
						panic(fmt.Errorf("referencing local, but it does not identify as one!"))
					}
				}

				objSegmentRemap[i].Fixups = append(objSegmentRemap[i].Fixups, OmfObjectFixup{
					Offset:   fixup.offset,
					Relative: fixup.relative,
					Label:    ext.label,
					Local:    ext.local,
				})
			} else {
				panic("Wait, no!")
			}
		}
	}

	return obj, nil
}

func ParseOmfObject(data []byte) (OmfObject, int, error) {
	builder := omfObjectBuilder{
		ledatas: map[uint16][]byte{},
		fixups:  map[uint16][]omfObjectFixup{},
	}

	var parsingError error

	i := 0
	for {
		tag := data[i + 0]
		size := int(data[i + 1]) | (int(data[i + 2]) << 8)
		chk := data[i + int(size) + 2]
		content := data[i + 3:][:size - 1]
		if chk != 0 {
			var sum uint8
			for _, v := range data[i:][:size + 3] {
				sum += v
			}
			if sum != 0 {
				return OmfObject{}, i, fmt.Errorf("Failed checksum")
			}
		}
		i += int(size) + 3

		if tag == 0x8a {
			// the object is finished
			break
		}

		if errors.Is(parsingError, ErrSkipParsing) {
			continue
		}

		switch tag {
		case 0x80: // OMF Start
			name := string(content[1:][:content[0]])
			builder.setName(name)
		case 0x88: // Comment
			if bytes.Equal(content, []byte{0x80, 0xaa, 0x38, 0x30, 0x33, 0x38, 0x36}) {
				// skip pharlap idk!
				parsingError = ErrPharLapFormat
			}
		case 0x95: // CMD_LINNUM32
			continue
		case 0x9a: // CMD_GRPDEF
			// Group definitions, probably unused in my case
			continue
		case 0xc3: // CMD_COMDAT32
			parsingError = fmt.Errorf("communal data records: %w", ErrFeatureNotImplemented)
		case 0xa3: // CMD_LIDATA32
			parsingError = fmt.Errorf("repeated data records: %w", ErrFeatureNotImplemented)

		case 0x96: // CMD_LNAMES, aka Section and Segment Names
			builder.parseLnames(content)

		case 0x99: // CMD_SEGDEF32
			// Segment definitions
			builder.parseSegdef32(content)

		case 0xa0, 0xa1: // CMD_LEDATA, CMD_LEDATA32
			builder.parseLedata(content, (tag & 1) != 0)

		case 0x9d: // CMD_FIXUPP32
			if err := builder.parseFixup32(content); err != nil {
				parsingError = err
			}

		case 0x90, 0x91, 0xb6, 0xb7: // CMD_PUBDEF, CMD_PUBDEF32, CMD_LPUBDEF, CMD_LPUBDEF32
			isLocal := (tag & 0xfe) == 0xb6
			is32 := (tag & 1) != 0

			if err := builder.parsePubdef(content, isLocal, is32); err != nil {
				parsingError = err
			}

		case 0x8c: // CMD_EXTDEF
			builder.parseExtdef16(content, false)
		case 0xb4: // CMD_LEXTDEF
			builder.parseExtdef16(content, true)

		default:
			fmt.Printf("%02x: %d (%02x) %02x %q\n", tag, size, chk, content, content)
			panic("TODO")
		}
	}

	if parsingError != nil {
		return OmfObject{}, i, parsingError
	}

	obj, err := builder.build()
	return obj, i, err
}

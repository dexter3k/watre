package omf

import (
	"encoding/binary"
	"fmt"
)

const (
	kFrameIsSpecifiedByASegmentIndex      = 0
	kFrameIsSpecifiedByAGroupIndex        = 1
	kFrameIsSpecifiedByAnExternalIndex    = 2
	kFrameIsSpecifiedByAFrameNumber       = 3
	kFrameIsSpecifiedByThePreviousSegment = 4
	kFrameIsSpecifiedByTheTarget          = 5
	kFrameIsNotSpecified                  = 6

	kTargetIsSpecifiedByASegmentIndex   = 0
	kTargetIsSpecifiedByAGroupIndex     = 1
	kTargetIsSpecifiedByAnExternalIndex = 2
	kTargetIsSpecifiedByAFrameNumber    = 3

	kFixupClass32BitOffset  = 9
	kFixupClass48BitPointer = 11
)

type Location int
const (
	LocationText Location = iota
	LocationBegData
	LocationData
	LocationStatic
	LocationConst
	LocationStack
	LocationCount
)

func (l Location) String() string {
	switch l {
	case LocationText:
		return "CODE"
	case LocationBegData:
		return "BEGDATA"
	case LocationData:
		return "DATA"
	case LocationStatic:
		return "BSS"
	case LocationConst:
		return "CONST"
	case LocationStack:
		return "STACK"
	default:
		return fmt.Sprintf("Location(%d)", int(l))
	}
}

func LocationFromName(name string) (Location, error) {
	switch name {
	case "CODE":
		return LocationText, nil
	case "BEGDATA":
		return LocationBegData, nil
	case "DATA":
		return LocationData, nil
	case "BSS":
		return LocationStatic, nil
	case "CONST":
		return LocationConst, nil
	case "STACK":
		return LocationStack, nil
	default:
		return Location(0), fmt.Errorf("Unknown location: %q", name)
	}
}

type SegmentRef struct {
	Location Location
	Name     string
	Offset   uint32
}

func (r SegmentRef) String() string {
	return fmt.Sprintf("%s:%q:%08x", r.Location, r.Name, r.Offset)
}

type RelocationType int
const (
	RelocationAbsolute32 RelocationType = iota
	RelocationRelative32
	RelocationAbsolute48
)

func (t RelocationType) IsRelative() bool {
	return t == RelocationRelative32
}

func (t RelocationType) Size() int {
	if t == RelocationAbsolute48 {
		return 6
	}

	return 4
}

func (t RelocationType) String() string {
	switch t {
	case RelocationAbsolute32:
		return "Absolute 32-bit"
	case RelocationRelative32:
		return "Relative 32-bit"
	case RelocationAbsolute48:
		return "Absolute 48-bit"
	default:
		return fmt.Sprintf("RelocationType(%d)", t)
	}
}

type Relocation interface {
	GetType() RelocationType
}

type LocalRelocation struct {
	Type     RelocationType
	LocalRef SegmentRef
}

func (r *LocalRelocation) GetType() RelocationType {
	return r.Type
}

type GlobalRelocation struct {
	Type       RelocationType
	GlobalName string
	Offset     uint32
}

func (r *GlobalRelocation) GetType() RelocationType {
	return r.Type
}

type Segment struct {
	Name    string
	Data    []byte
	Relocs  map[uint32]Relocation
	Exports map[string]uint32
}

type Object struct {
	Name     string
	Segments [LocationCount]([]*Segment)
}

func ParseOmfObject(data []byte) (*Object, int, error) {
	le := binary.LittleEndian

	loadIndex := func(data []byte) (uint16, []byte) {
		if (data[0] & 0x80) != 0 {
			return (uint16(data[0] & 0x7f) << 8) | uint16(data[1]), data[2:]
		} else {
			return uint16(data[0]), data[1:]
		}
	}

	object := &Object{}

	lnames := []string{}

	type segment struct {
		Location   Location
		Name       string
		Size       uint32
		Attributes uint8
	}
	segments := []segment{}

	type extern struct {
		name  string
		local bool
	}
	externs := []extern{}

	localExports := map[string]SegmentRef{}
	globalExports := map[string]SegmentRef{}

	type localImport struct {
		ref   SegmentRef
		reloc GlobalRelocation
	}
	localImports := []localImport{}

	var lastLedataSegmentRef SegmentRef

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
				return nil, i, fmt.Errorf("checksum failed")
			}
		}

		content := data[i + 3:][:size - 1]
		i += size + 3

		switch tag {
		case 0x80: // OMF Object Start
			objName := string(content[1:][:content[0]])
			content = content[1 + content[0]:]
			object.Name = objName
		case 0x8a: // OMF Object End
			break tagLoop
		case 0x88, 0x95, 0x9a: // LINKER_COMMENT, CMD_LINNUM32, CMD_GRPDEF
			// Skip
		case 0x96: // OMF_LNAMES
			for len(content) > 0 {
				name := string(content[1:][:content[0]])
				content = content[1 + content[0]:]
				lnames = append(lnames, name)
			}
		case 0x99: // CMD_SEGDEF32
			segmentAttributes := content[0]
			segmentSize := le.Uint32(content[1:][:4])
			content = content[5:]

			var segmentName, segmentSection uint16
			segmentName, content = loadIndex(content)
			segmentSection, content = loadIndex(content)
			/*segmentOverlay*/_, content = loadIndex(content)

			segmentName -= 1
			segmentSection -= 1

			if location, err := LocationFromName(lnames[segmentSection]); err != nil {
				return nil, i, err
			} else {
				segments = append(segments, segment{
					Location:   location,
					Name:       lnames[segmentName],
					Size:       segmentSize,
					Attributes: segmentAttributes,
				})

				segment := &Segment{
					Name: lnames[segmentName],
				}
				if segmentSize > 0 {
					segment.Data = make([]byte, segmentSize)
				}
				object.Segments[location] = append(object.Segments[location], segment)
			}
		case 0x8c, 0xb4: // CMD_EXTDEF, CMD_LEXTDEF
			importsLocal := tag == 0xb4
			for len(content) > 0 {
				importName := string(content[1:][:content[0]])
				content = content[1 + content[0]:]
				if importName == "" {
					continue
				}

				externs = append(externs, extern{
					name:  importName,
					local: importsLocal,
				})
			}
		case 0x90, 0x91, 0xb6, 0xb7: // CMD_PUBDEF, CMD_PUBDEF32, CMD_LPUBDEF, CMD_LPUBDEF32
			exportsLocal := (tag & 0xfe) == 0xb6
			exports32 := (tag & 1) != 0

			var exportsSegment uint16
			_, content = loadIndex(content)
			exportsSegment, content = loadIndex(content)

			ignoreTheseExports := false
			if exportsSegment == 0 {
				// These exports refer to a frame number
				// We really don't care. But we still want to
				// parse the object correctly
				content = content[2:]
				ignoreTheseExports = true
			}

			exportsSegment -= 1

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
				if exportType != 0 {
					return nil, i, fmt.Errorf("Unknown export type: %d", exportType)
				}

				if ignoreTheseExports {
					// ignored
					continue
				}

				if exportsLocal {
					localExports[exportName] = SegmentRef{
						Location: segments[exportsSegment].Location,
						Name:     segments[exportsSegment].Name,
						Offset:   exportOffset,
					}
				} else {
					globalExports[exportName] = SegmentRef{
						Location: segments[exportsSegment].Location,
						Name:     segments[exportsSegment].Name,
						Offset:   exportOffset,
					}

					for _, subSeg := range object.Segments[segments[exportsSegment].Location] {
						if subSeg.Name != segments[exportsSegment].Name {
							continue
						}

						if subSeg.Exports == nil {
							subSeg.Exports = map[string]uint32{}
						}
						subSeg.Exports[exportName] = exportOffset

						break
					}
				}
			}
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

			lastLedataSegmentRef = SegmentRef{
				Location: segments[ledataSegment].Location,
				Name:     segments[ledataSegment].Name,
				Offset:   ledataOffset,
			}

			for _, subSeg := range object.Segments[segments[ledataSegment].Location] {
				if subSeg.Name != segments[ledataSegment].Name {
					continue
				}

				copy(subSeg.Data[ledataOffset:], content)
				break
			}
			content = content[len(content):]
		case 0xa3: // CMD_LIDATA32
			var lidataSegment uint16
			lidataSegment, content = loadIndex(content)
			lidataSegment -= 1

			lidataOffset := le.Uint32(content[:4])
			content = content[4:]

			lastLedataSegmentRef = SegmentRef{
				Location: segments[lidataSegment].Location,
				Name:     segments[lidataSegment].Name,
				Offset:   lidataOffset,
			}

			var segment *Segment
			for _, seg := range object.Segments[segments[lidataSegment].Location] {
				if seg.Name == segments[lidataSegment].Name {
					segment = seg
					break
				}
			}
			if segment == nil {
				panic("Unable to locate a segment that should be there")
			}

			dataPtr := segment.Data[lidataOffset:]

			var extractBlock func(src, dst []byte) (int, int)
			extractBlock = func(src, dst []byte) (int, int) {
				repeatCount := int(le.Uint32(src[0:4]))
				blockCount := int(le.Uint16(src[4:6]))
				src = src[6:]

				blockSize := 0
				contentSize := 0
				if blockCount == 0 {
					contentSize = int(src[0])
					blockSize += contentSize + 1
					src = src[1:]
					copy(dst, src[:contentSize])
				} else {
					for i := 0; i < blockCount; i++ {
						bs, cs := extractBlock(src[blockSize:], dst[contentSize:])
						blockSize += bs
						contentSize += cs
					}
				}

				// Repeat this block
				for i := 1; i < repeatCount; i++ {
					copy(dst[contentSize * i:], dst[:contentSize])
				}

				return blockSize + 6, contentSize * repeatCount
			}

			for len(content) > 0 {
				blockSize, contentSize := extractBlock(content, dataPtr)
				content = content[blockSize:]
				dataPtr = dataPtr[contentSize:]
			}
		case 0x9d: // CMD_FIXUPP32
			// TODO: Support 0x9C - CMD_FIXUPP
			// - highest bit of class must be zero
			// - extra displacement is 16 bits, not 32

			for len(content) > 0 {
				fixupCursor0 := content[0]
				fixupCursor1 := content[1]
				fixupCursor2 := content[2]
				content = content[3:]

				if (fixupCursor0 & 0x80) == 0 {
					return nil, i, fmt.Errorf("Threaded fixups are not supported: %02x", fixupCursor0)
				}
				if (fixupCursor2 & 0x88) != 0 {
					return nil, i, fmt.Errorf("Threaded fixups are not supported: %02x", fixupCursor2)
				}

				fixupAbsolute := (fixupCursor0 & 0x40) != 0
				fixupClass := (fixupCursor0 >> 2) & 0xf
				fixupOffset := (uint16(fixupCursor0 & 3) << 8) + uint16(fixupCursor1)

				fixupFrame := (fixupCursor2 >> 4) & 0x7
				fixupHasDisplacement := (fixupCursor2 & 0x4) == 0
				fixupTarget := fixupCursor2 & 0x3

				var fid uint16
				if fixupFrame == kFrameIsSpecifiedByASegmentIndex || fixupFrame == kFrameIsSpecifiedByAGroupIndex || fixupFrame == kFrameIsSpecifiedByAnExternalIndex {
					fid, content = loadIndex(content)
				} else if fixupFrame == kFrameIsSpecifiedByAFrameNumber {
					return nil, i, fmt.Errorf("Using an absolute frame number to specify a fixup frame is not supported.")
				} else if fixupFrame == kFrameIsSpecifiedByThePreviousSegment {
					// This is probably almost supported. I'm not quite sure what this is,
					// but I have not seen this in any libs that I've tested.
					return nil, i, fmt.Errorf("Using current segment to speficy as a fixup frame is not supported.")
				} else if fixupFrame >= kFrameIsNotSpecified {
					return nil, i, fmt.Errorf("Fixup frame is not specified.")
				}

				var tid uint16
				tid, content = loadIndex(content)

				if fixupFrame == kFrameIsSpecifiedByAnExternalIndex {
					// We're assuming that the index for the frame would
					// be exactly the same as the one speficied for the target
					// So this is essentially a kFrameIsSpecifiedByTheTarget,
					// just with a redundand index

					// TODO: find libs that actually specify kFrameIsSpecifiedByAnExternalIndex.

					if fid != tid {
						return nil, i, fmt.Errorf("The frame is specified by an external index, but it differs form target's index?")
					}
				} else if fixupFrame == kFrameIsSpecifiedByTheTarget {
					fixupFrame = fixupTarget & 0x3
					fid = tid
				}

				var displacement uint32
				if fixupHasDisplacement {
					displacement = le.Uint32(content[:4])
					content = content[4:]
				}

				if fixupClass != kFixupClass32BitOffset && fixupClass != kFixupClass48BitPointer {
					return nil, i, fmt.Errorf("Only 32-bit or 48-bit fixups are supported.")
				}
				
				// TODO: If I understood correctly, the FRAME is used to adjust for
				// segmentation, so it does not affect anything in 32-bit and 48-bit fixups
				// which are used in protected mode only

				var relocType RelocationType
				if fixupClass == kFixupClass32BitOffset {
					if fixupAbsolute {
						relocType = RelocationAbsolute32
					} else {
						relocType = RelocationRelative32
					}
				} else if fixupClass == kFixupClass48BitPointer {
					if fixupAbsolute {
						relocType = RelocationAbsolute48
					} else {
						return nil, i, fmt.Errorf("Relative fixups are not expected for 48-bit pointers.")
					}
				}

				var segment *Segment
				for _, seg := range object.Segments[lastLedataSegmentRef.Location] {
					if seg.Name == lastLedataSegmentRef.Name {
						segment = seg
						break
					}
				}

				if segment == nil {
					// TODO: make this an error, not a panic
					panic("FIXUP, but no previous LEDATA or LIDATA?")
				}

				// Find out where the reloc is placed
				offsetWithinSegment := lastLedataSegmentRef.Offset + uint32(fixupOffset)

				// Get displacement specified in the data
				displacement += le.Uint32(segment.Data[offsetWithinSegment:][:4])

				// And erase it, to keep everything in one place
				le.PutUint32(segment.Data[offsetWithinSegment:][:4], 0)

				if fixupTarget == kTargetIsSpecifiedByASegmentIndex {
					segmentIndex := tid - 1

					if segment.Relocs == nil {
						segment.Relocs = map[uint32]Relocation{}
					}

					segment.Relocs[offsetWithinSegment] = &LocalRelocation{
						Type:     relocType,
						LocalRef: SegmentRef{
							Location: segments[segmentIndex].Location,
							Name:     segments[segmentIndex].Name,
							Offset:   displacement,
						},
					}
				} else if fixupTarget == kTargetIsSpecifiedByAnExternalIndex {
					externIndex := tid - 1

					// If the extern is local, we will resolve it later into an offset later
					// So that only global refs require names
					if externs[externIndex].local {
						localImports = append(localImports, localImport{
							ref: SegmentRef{
								Location: lastLedataSegmentRef.Location,
								Name:     lastLedataSegmentRef.Name,
								Offset:   offsetWithinSegment,
							},

							reloc: GlobalRelocation{
								Type:       relocType,
								GlobalName: externs[externIndex].name,
								Offset:     displacement,
							},
						})
					} else {
						if segment.Relocs == nil {
							segment.Relocs = map[uint32]Relocation{}
						}

						segment.Relocs[offsetWithinSegment] = &GlobalRelocation{
							Type:       relocType,
							GlobalName: externs[externIndex].name,
							Offset:     displacement,
						}
					}
				} else if fixupTarget == kTargetIsSpecifiedByAGroupIndex {
					// This could be easily supported, but
					// 1) We don't parse groups
					// 2) I haven't seen this being used anywhere
					return nil, i, fmt.Errorf("Using a group to specify a fixup target is not supported.")
				} else if fixupTarget == kTargetIsSpecifiedByAFrameNumber {
					return nil, i, fmt.Errorf("Using an absolute frame number to specify a fixup target is not supported.")
				}
			}
		default:
			return nil, i, fmt.Errorf("unknown omf object tag: %02x\n", tag)
		}
	}

	// To make local resolutions more uniform, resolve
	// local imports to actual segment offsets
	for _, imp := range localImports {
		for _, subSeg := range object.Segments[imp.ref.Location] {
			if subSeg.Name != imp.ref.Name {
				continue
			}

			if subSeg.Relocs == nil {
				subSeg.Relocs = map[uint32]Relocation{}
			}

			subSeg.Relocs[imp.ref.Offset] = &LocalRelocation{
				Type:     imp.reloc.Type,
				LocalRef: SegmentRef{
					Location: localExports[imp.reloc.GlobalName].Location,
					Name:     localExports[imp.reloc.GlobalName].Name,
					Offset:   localExports[imp.reloc.GlobalName].Offset + imp.reloc.Offset,
				},
			}

			break
		}
	}

	// Also normalize relocs to local global symbols
	for location := Location(0); location < LocationCount; location++ {
		for _, segment := range object.Segments[location] {
			keys := make([]uint32, 0, len(segment.Relocs))
			for key := range segment.Relocs {
				keys = append(keys, key)
			}

			for it := 0; it < len(keys); it++ {
				reloc, ok := segment.Relocs[keys[it]].(*GlobalRelocation)
				if !ok {
					continue
				}

				// Not from this module
				if _, found := globalExports[reloc.GlobalName]; !found {
					continue
				}

				segment.Relocs[keys[it]] = &LocalRelocation{
					Type:     reloc.Type,
					LocalRef: SegmentRef{
						Location: globalExports[reloc.GlobalName].Location,
						Name:     globalExports[reloc.GlobalName].Name,
						Offset:   globalExports[reloc.GlobalName].Offset + reloc.Offset,
					},
				}
			}
		}
	}

	// Remove empty segments
	for location := Location(0); location < LocationCount; location++ {
		newSegments := []*Segment{}
		for _, segment := range object.Segments[location] {
			if len(segment.Data) > 0 {
				newSegments = append(newSegments, segment)
				continue
			}
			if len(segment.Relocs) > 0 {
				newSegments = append(newSegments, segment)
				continue
			}
			if len(segment.Exports) > 0 {
				newSegments = append(newSegments, segment)
				continue
			}
		}

		object.Segments[location] = newSegments
	}

	return object, i, nil
}

func Parse(data []byte) ([]*Object, error) {
	if data[0] != 0xf0 || data[1] == 0x01 {
		return nil, fmt.Errorf("Unknown OMF header: %02x", data[:2])
	}

	le := binary.LittleEndian
	omfPageSize := le.Uint16(data[1:][:2]) + 3
	// omfDictOffset := le.Uint32(data[3:][:4])
	// omfDictSize := le.Uint16(data[7:][:2])
	// omfFlags := data[9]

	if omfPageSize < 10 {
		return nil, fmt.Errorf("Page size won't fit even the header")
	} else if (omfPageSize & (omfPageSize - 1)) != 0 {
		return nil, fmt.Errorf("Page size is supposed to be a power of two")
	}

	objects := []*Object{}

	pageSizeMask := int(omfPageSize) - 1

	i := 1 * int(omfPageSize)
	for data[i] != 0xf1 {
		object, length, err := ParseOmfObject(data[i:])
		if err != nil {
			return nil, err
		}

		objects = append(objects, object)

		i += length
		i_aligned_up := (i + pageSizeMask) & ^pageSizeMask
		i = i_aligned_up
	}

	return objects, nil
}

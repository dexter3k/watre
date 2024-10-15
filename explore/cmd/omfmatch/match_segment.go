package main

import (
	"encoding/binary"
	"fmt"
	"slices"
	"maps"
	"strings"
	"strconv"
	"bytes"

	"github.com/dexter3k/watre/explore/ext/omf"
)

type segmentMatch struct {
	// Segment info
	object   string
	location omf.Location
	segment  string

	// Possible address of the segment
	address uint32
	// Or if it can be anywhere
	couldBeAnywhere bool

	// Constraints on possible addresses of dependencies
	globals map[string]uint32
	locals  map[string]uint32
}

func splitLocalSegmentName(name string) (string, omf.Location, string) {
	object, err := strconv.QuotedPrefix(name)
	if err != nil {
		panic(fmt.Errorf("Unable to decode segment object: %s, because %w", name, err))
	}
	name = name[len(object) + 1:]
	object, err = strconv.Unquote(object)
	if err != nil {
		panic(fmt.Errorf("Unable to decode segment object: %s, because %w", name, err))
	}

	parts := strings.SplitN(name, ":", 2)
	if len(parts) != 2 {
		panic(fmt.Errorf("Failed to split local segment name: %s", name))
	}

	for location := omf.LocationText; location < omf.LocationCount; location++ {
		if parts[0] != location.String() {
			continue
		}

		if res, err := strconv.Unquote(parts[1]); err != nil {
			panic(fmt.Errorf("Unable to decode segment name: %s, because %w", name, err))
		} else {
			return object, location, res
		}
	}

	panic(fmt.Errorf("Unable to decode segment location: %s", name))
}

func mapsHaveCollisions(a, b map[string]uint32) bool {
	for k, va := range a {
		if vb, found := b[k]; found && va != vb {
			return true
		}
	}

	for k, vb := range b {
		if va, found := a[k]; found && va != vb {
			return true
		}
	}

	return false
}

func combineMaps(a, b map[string]uint32) map[string]uint32 {
	res := map[string]uint32{}
	for k, v := range a {
		res[k] = v
	}
	for k, v := range b {
		res[k] = v
	}
	return res
}

type matchingContext struct {
	objects []*omf.Object

	importCache map[string]*importCacheEntry

	locationMap  map[omf.Location][]byte
	locationBase map[omf.Location]uint32

	lowAddress  uint32
	highAddress uint32
}

type singleObjectValidMatch struct {
	locals  map[string]uint32
	globals map[string]uint32
}

func (m *matchingContext) trySegmentMatch(object *omf.Object, segmentFullName string, segment *omf.Segment, data []byte, base uint32, globals, locals map[string]uint32) bool {
	globalRelocs := maps.Clone(globals)
	localRelocs := maps.Clone(locals)

	if !tryMatchingSegmentTo(
		segment.Data,
		data, base, object.Name, segment.Relocs,
		m.lowAddress, m.highAddress,
		globalRelocs, localRelocs,
	) {
		return false
	}

	// Check self-references are correct
	if address, found := localRelocs[segmentFullName]; found && address != base {
		return false
	}
	localRelocs[segmentFullName] = base

	// Check and add exported globals
	for name, offset := range segment.Exports {
		if prev, found := globalRelocs[name]; found && prev != base + offset {
			return false
		}

		globalRelocs[name] = base + offset
	}

	for k, v := range localRelocs {
		locals[k] = v
	}
	for k, v := range globalRelocs {
		globals[k] = v
	}

	return true
}

func (m *matchingContext) getObjectByName(name string) *omf.Object {
	for _, object := range m.objects {
		if object.Name == name {
			return object
		}
	}

	return nil
}

type importCacheEntry struct {
	obj *omf.Object
	loc omf.Location
	seg *omf.Segment
	off uint32
}

func (m *matchingContext) resolveImport(globalName string, address uint32) (*omf.Object, omf.Location, *omf.Segment, uint32) {
	if entry, found := m.importCache[globalName]; found {
		return entry.obj, entry.loc, entry.seg, address - entry.off
	}

	for _, object := range m.objects {
		for location, _ := range m.locationMap {
			for _, segment := range object.Segments[location] {
				offset, found := segment.Exports[globalName]
				if !found {
					continue
				}

				m.importCache[globalName] = &importCacheEntry{
					obj: object,
					loc: location,
					seg: segment,
					off: offset,
				}
				return object, location, segment, address - offset
			}
		}
	}

	return nil, omf.Location(0), nil, 0
}

func (m *matchingContext) getSegmentMatches(object *omf.Object, location omf.Location, segment *omf.Segment) ([]singleObjectValidMatch, bool) {
	var matches []singleObjectValidMatch

	if len(segment.Data) == 0 {
		return matches, true
	}

	segmentFullName := fmt.Sprintf("%q:%s:%q", object.Name, location, segment.Name)
	data := m.locationMap[location]
	base := m.locationBase[location]

	firstNonRelocatedByteIndex := len(segment.Data)
	for i := 0; i < len(segment.Data); i++ {
		if reloc, found := segment.Relocs[uint32(i)]; found {
			i += reloc.GetType().Size() - 1
			continue
		}

		firstNonRelocatedByteIndex = i
		break
	}

segmentSearchLoop:
	for i := 0; i <= len(data) - len(segment.Data); i++ {
		if firstNonRelocatedByteIndex != len(segment.Data) {
			j := bytes.IndexByte(data[i + firstNonRelocatedByteIndex:], segment.Data[firstNonRelocatedByteIndex])
			if j == -1 {
				break
			}
			i += j
		}
		if i > len(data) - len(segment.Data) {
			break
		}

		globalRelocs := map[string]uint32{}
		localRelocs := map[string]uint32{}

		if !m.trySegmentMatch(
			object, segmentFullName, segment,
			data[i:], base + uint32(i),
			globalRelocs, localRelocs,
		) {
			continue
		}

		// Check all local dependencies
		checkedLocals := map[string]struct{}{}
		checkedGlobals := map[string]struct{}{}
		prevLocalAndGlobalCount := 0
		for prevLocalAndGlobalCount < len(localRelocs) + len(globalRelocs) {
			prevLocalAndGlobalCount = len(localRelocs) + len(globalRelocs)

			for localName, address := range localRelocs {
				if _, found := checkedLocals[localName]; found {
					continue
				}
				checkedLocals[localName] = struct{}{}

				objName, loc, nm := splitLocalSegmentName(localName)
				// Check the address is within bounds of the section
				if address < m.locationBase[loc] || address > m.locationBase[loc] + uint32(len(m.locationMap[loc])) {
					continue segmentSearchLoop
				}

				obj := m.getObjectByName(objName)
				depSeg := obj.GetSegment(loc, nm)
				if depSeg == nil {
					panic(fmt.Errorf("%s: Missing dependent segment: %s", segmentFullName, localName))
				}

				if !m.trySegmentMatch(
					obj, localName, depSeg,
					m.locationMap[loc][address - m.locationBase[loc]:], address,
					globalRelocs, localRelocs,
				) {
					continue segmentSearchLoop
				}
			}

			for globalName, address := range globalRelocs {
				if _, found := checkedGlobals[globalName]; found {
					continue
				}
				checkedGlobals[globalName] = struct{}{}

				obj, loc, seg, segAddress := m.resolveImport(globalName, address)
				if obj == nil {
					continue
				}

				if segAddress < m.locationBase[loc] || segAddress - m.locationBase[loc] >= uint32(len(m.locationMap[loc])) {
					continue segmentSearchLoop
				}

				ln := fmt.Sprintf("%q:%s:%q", obj.Name, loc, seg.Name)

				if !m.trySegmentMatch(
					obj, ln, seg,
					m.locationMap[loc][segAddress - m.locationBase[loc]:], segAddress,
					globalRelocs, localRelocs,
				) {
					continue segmentSearchLoop
				}
			}
		}

		matches = append(matches, singleObjectValidMatch{
			globals: globalRelocs,
			locals:  localRelocs,
		})
	}

	return matches, false
}

func (m *matchingContext) tryMatchingExport(exportName string, baseGlobals, baseLocals map[string]uint32) bool {
	return false
}

func mapToString(m map[string]uint32) string {
	var parts []string
	for k, v := range m {
		parts = append(parts, fmt.Sprintf("%q=%d", k, v))
	}
	slices.Sort(parts)
	return strings.Join(parts, ",")
}

func makeMatchesUnique(matches []singleObjectValidMatch) []singleObjectValidMatch {
	result := []singleObjectValidMatch{}

	taken := map[string]struct{}{}
	for _, match := range matches {
		key := mapToString(match.locals) + "|" + mapToString(match.globals)
		if _, found := taken[key]; found {
			continue
		}

		taken[key] = struct{}{}
		result = append(result, match)
	}

	return result
}

func (m *matchingContext) matchEntireObject(object *omf.Object) []singleObjectValidMatch {
	matchesOnThisObject := []singleObjectValidMatch{}

	for location, _ := range m.locationMap {
		if location == omf.LocationStatic {
			continue
		}
		for _, segment := range object.Segments[location] {
			matchesOnThisSegment, skip := m.getSegmentMatches(object, location, segment)
			if skip {
				continue
			}

			if len(matchesOnThisSegment) == 0 {
				return nil
			}

			if len(matchesOnThisObject) == 0 {
				matchesOnThisObject = matchesOnThisSegment
			} else {
				// Explode matches with previous finds
				// so if we've found A, B, C
				// and in this segment D, E
				// Leave AD, BD, CD, AE, BE, CE
				combinedMatches := []singleObjectValidMatch{}
				for _, matchThisSegment := range matchesOnThisSegment {
					for _, matchPreviously := range matchesOnThisObject {
						if mapsHaveCollisions(matchThisSegment.locals, matchPreviously.locals) {
							continue
						}
						if mapsHaveCollisions(matchThisSegment.globals, matchPreviously.globals) {
							continue
						}

						combinedMatches = append(combinedMatches, singleObjectValidMatch{
							globals: combineMaps(matchThisSegment.globals, matchPreviously.globals),
							locals: combineMaps(matchThisSegment.locals, matchPreviously.locals),
						})
					}
				}

				if len(combinedMatches) == 0 {
					return nil
				}

				matchesOnThisObject = combinedMatches
			}

			// And collapse exactly equal matches, to leave just the unique ones
			matchesOnThisObject = makeMatchesUnique(matchesOnThisObject)
		}
	}

	return matchesOnThisObject
}

func matchIndividual(objects []*omf.Object, locations map[omf.Location][]byte, locationBases map[omf.Location]uint32) {
	con := matchingContext{
		objects: objects,

		importCache: map[string]*importCacheEntry{},

		locationMap:  locations,
		locationBase: locationBases,

		lowAddress:  0x00400000,
		highAddress: 0x006e2a00 - 1,
	}

	uniqueMatches := map[string]singleObjectValidMatch{}
	nonUniqueMatches := map[string][]singleObjectValidMatch{}

	for _, object := range objects {
		matches := con.matchEntireObject(object)
		// for i, match := range matches {
		// 	fmt.Printf("%d/%d: %q:\n", i + 1, len(matches), object.Name)
		// 	for _, name := range slices.Sorted(maps.Keys(match.locals)) {
		// 		fmt.Printf(" - %s: %08x\n", name, match.locals[name])
		// 	}
		// 	for _, name := range slices.Sorted(maps.Keys(match.globals)) {
		// 		fmt.Printf(" - %s: %08x\n", name, match.globals[name])
		// 	}
		// }

		if len(matches) == 0 {
			continue
		}
		if len(matches) == 1 {
			uniqueMatches[object.Name] = matches[0]
		} else {
			nonUniqueMatches[object.Name] = matches
		}
	}

	uniqueNames := slices.SortedFunc(maps.Keys(uniqueMatches), func(a, b string) int {
		lhs := len(uniqueMatches[a].locals) + len(uniqueMatches[a].globals)
		rhs := len(uniqueMatches[b].locals) + len(uniqueMatches[b].globals)
		return rhs - lhs
	})

	combined := uniqueMatches[uniqueNames[0]]
	for _, name := range uniqueNames[1:] {
		if mapsHaveCollisions(combined.locals, uniqueMatches[name].locals) {
			continue
		}
		if mapsHaveCollisions(combined.globals, uniqueMatches[name].globals) {
			continue
		}

		combined.locals = combineMaps(combined.locals, uniqueMatches[name].locals)
		combined.globals = combineMaps(combined.globals, uniqueMatches[name].globals)
	}

	alreadyAdded := map[string]struct{}{}
	for name, matches := range nonUniqueMatches {
		if _, found := alreadyAdded[name]; found {
			continue
		}

		passed := []singleObjectValidMatch{}

		for _, match := range matches {
			if mapsHaveCollisions(combined.locals, match.locals) {
				continue
			}
			if mapsHaveCollisions(combined.globals, match.globals) {
				continue
			}

			passed = append(passed, match)
		}

		if len(passed) > 1 {
			fmt.Printf("Multiple (%d) matches for %s\n", len(passed), name)
		} else if len(passed) == 1 {
			combined.locals = combineMaps(combined.locals, passed[0].locals)
			combined.globals = combineMaps(combined.globals, passed[0].globals)
		}
	}

	for _, name := range slices.Sorted(maps.Keys(combined.locals)) {
		fmt.Printf(" - %s: %08x\n", name, combined.locals[name])
	}
	for _, name := range slices.Sorted(maps.Keys(combined.globals)) {
		fmt.Printf(" - %s: %08x\n", name, combined.globals[name])
	}

	// addressToSegment := map[uint32]string{}
	// for segment, address := range combined.locals {
	// 	addressToSegment[address] = segment
	// }

	// for _, address := range slices.Sorted(maps.Keys(addressToSegment)) {
	// 	fmt.Printf("%08x: %s\n", address, addressToSegment[address])
	// }
}

func tryMatchingSegmentTo(segment, section []byte, sectionBase uint32, objectName string, relocMap map[uint32]omf.Relocation, spaceLowerBound, spaceUpperBound uint32, globalRelocs, localRelocs map[string]uint32) bool {
	if len(segment) == 0 {
		return true
	}

	if len(section) < len(segment) {
		return false
	}

	newGlobalRelocs := map[string]uint32{}
	newLocalRelocs := map[string]uint32{}

	for i := 0; i < len(segment); i++ {
		rel, found := relocMap[uint32(i)]
		if !found {
			if segment[i] != section[i] {
				return false
			}

			continue
		}

		target := binary.LittleEndian.Uint32(section[i:][:4])
		target -= rel.GetOffset()

		switch rel.GetType() {
		case omf.RelocationAbsolute32:
			// no additional adjustments
		case omf.RelocationRelative32:
			target += sectionBase
			target += uint32(i)
			target += 4
		default:
			panic(fmt.Errorf("Unknown relocation kind: %s", rel.GetType()))
		}

		if target < spaceLowerBound || target > spaceUpperBound {
			return false
		}

		name := rel.GetName()

		switch reloc := rel.(type) {
		case *omf.GlobalRelocation:
			if prev, found := globalRelocs[name]; found {
				if prev != target {
					return false
				}

				break
			}

			if prev, found := newGlobalRelocs[name]; found && prev != target {
				return false
			}

			newGlobalRelocs[name] = target
		case *omf.LocalRelocation:
			name = fmt.Sprintf("%q:%s", objectName, name)
			if prev, found := localRelocs[name]; found {
				if prev != target {
					return false
				}

				break
			}

			if prev, found := newLocalRelocs[name]; found && prev != target {
				return false
			}

			newLocalRelocs[name] = target
		default:
			panic(fmt.Errorf("Unknown relocation type: %T", reloc))
		}

		i += rel.GetType().Size() - 1
	}

	for k, v := range newGlobalRelocs {
		globalRelocs[k] = v
	}
	for k, v := range newLocalRelocs {
		localRelocs[k] = v
	}

	return true
}

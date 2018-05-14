//
// keytab.go
//
// Copyright (c) 2018 Markku Rossi
//
// See the LICENSE file for the details on licensing.
//

package keytab

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"log"

	"github.com/markkurossi/kerberos/crypto"
)

type Keytab struct {
	Entries []KeyEntry
}

type KeyEntry struct {
	Principal  Principal
	Timestamp  int
	KeyVersion int
	EncType    crypto.EncType
	Key        []byte
}

type Principal struct {
	Components []Data
	NameType   int
}

type Data []byte

type input struct {
	data    []byte
	offset  int
	version int
	bo      binary.ByteOrder
}

func (i *input) Avail() int {
	return len(i.data) - i.offset
}

func (i *input) Int8() (int, error) {
	if i.Avail() < 1 {
		return 0, fmt.Errorf("Truncated keytab")
	}
	val := int(i.data[i.offset])
	i.offset += 1

	return val, nil
}

func (i *input) Int16() (int, error) {
	if i.Avail() < 2 {
		return 0, fmt.Errorf("Truncated keytab")
	}
	val := int(i.bo.Uint16(i.data[i.offset:]))
	i.offset += 2

	return val, nil
}

func (i *input) Int32() (int, error) {
	if i.Avail() < 4 {
		return 0, fmt.Errorf("Truncated keytab")
	}
	val := int(i.bo.Uint32(i.data[i.offset:]))
	i.offset += 4

	return val, nil
}

func (i *input) Data() ([]byte, error) {
	length, err := i.Int16()
	if err != nil {
		return nil, err
	}
	buf := make([]byte, length)
	_, err = i.Read(buf)
	return buf, err
}

func (i *input) Read(b []byte) (read int, err error) {
	n := len(b)

	if i.Avail() < n {
		read = i.Avail()
		err = io.EOF
	} else {
		read = n
	}
	copy(b, i.data[i.offset:i.offset+read])
	i.offset += read

	return
}

func (i *input) Skip(n int) (skipped int, err error) {
	if i.Avail() < n {
		skipped = i.Avail()
		err = io.EOF
	} else {
		skipped = n
	}
	i.offset += skipped

	return
}

func (i *input) RecordInput(d []byte) *input {
	return &input{
		data:    d,
		offset:  0,
		version: i.version,
		bo:      i.bo,
	}
}

func newInput(data []byte) (*input, error) {
	if len(data) < 2+4 {
		return nil, fmt.Errorf("Truncated keytab")
	}
	if data[0] != 5 {
		return nil, fmt.Errorf("Invalid version number %d", data[0])
	}

	var bo binary.ByteOrder

	switch data[1] {
	case 1:
		return nil, fmt.Errorf("Native byte order not implemented yet")
	case 2:
		bo = binary.BigEndian

	default:
		return nil, fmt.Errorf("Invalid byte order marker %d", data[1])
	}

	return &input{
		data:    data,
		offset:  2,
		version: int(data[1]),
		bo:      bo,
	}, nil
}

func Parse(data []byte) (*Keytab, error) {
	in, err := newInput(data)
	if err != nil {
		return nil, err
	}

	var keytab Keytab

	// Read all entries.
	for in.Avail() > 0 {
		length, err := in.Int32()
		if err != nil {
			return nil, err
		}
		if length < 0 {
			// Skip keytab `hole'.
			_, err = in.Skip(-length)
			if err != nil {
				return nil, err
			}
			continue
		}

		// Read and parse entry.

		entry := make([]byte, length)
		_, err = in.Read(entry)
		if err != nil {
			return nil, err
		}

		log.Printf("Entry:\n%s", hex.Dump(entry))

		keyEntry, err := ParseKeyEntry(in.RecordInput(entry))
		if err != nil {
			return nil, err
		}

		keytab.Entries = append(keytab.Entries, keyEntry)
	}

	return &keytab, nil
}

func ParseKeyEntry(in *input) (keyEntry KeyEntry, err error) {

	if keyEntry.Principal, err = ParsePrincipal(in); err != nil {
		return
	}
	if keyEntry.Timestamp, err = in.Int32(); err != nil {
		return
	}
	if keyEntry.KeyVersion, err = in.Int8(); err != nil {
		return
	}
	etype, err := in.Int16()
	if err != nil {
		return
	}
	keyEntry.EncType = crypto.EncType(etype)

	if keyEntry.Key, err = in.Data(); err != nil {
		return
	}

	return
}

func ParsePrincipal(in *input) (principal Principal, err error) {
	// Principal.
	numComponents, err := in.Int16()
	if err != nil {
		return
	}
	if in.version == 2 {
		// Real is included in version 1
		numComponents++
	}
	for i := 0; i < numComponents; i++ {
		var d []byte
		d, err = in.Data()
		if err != nil {
			return
		}
		log.Printf("Data[%d]:\n%s", i, hex.Dump(d))
		principal.Components = append(principal.Components, Data(d))
	}
	if in.version == 2 {
		principal.NameType, err = in.Int32()
		if err != nil {
			return
		}
	}

	return principal, nil
}

package ykoath

import "encoding/binary"

// OathOption describes options for OATH credentials
type OathOption byte

const (
	OathIncreasing = 1 << iota
	OathTouch
	OathExportable
)

// Put sends a "PUT" instruction, storing a new / overwriting an existing OATH
// credentials with an algorithm and type, 6 or 8 digits one-time password,
// shared secrets and touch-required bit
func (o *OATH) Put(name string, a Algorithm, t Type, digits uint8, key []byte, prop OathOption, counter uint32) error {

	var (
		alg = (0xf0|byte(a))&0x0f | byte(t)
		dig = byte(digits)
		prp []byte
		imf []byte
	)

	if prop != 0 {
		prp = write(0x78, []byte{byte(prop)})
	}

	if counter != 0 {
		imfVal := make([]byte, 4)
		binary.BigEndian.PutUint32(imfVal, counter)
		prp = write(0x7A, imfVal)
	}

	_, err := o.send(0x00, 0x01, 0x00, 0x00,
		write(0x71, []byte(name)),
		write(0x73, []byte{alg, dig}, key),
		prp,
		imf,
	)

	return err

}

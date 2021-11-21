package ykoath

import "encoding/binary"

// Put sends a "PUT" instruction, storing a new / overwriting an existing OATH
// credentials with an algorithm and type, 6 or 8 digits one-time password,
// shared secrets and touch-required bit
func (o *OATH) Put(name string, a Algorithm, t Type, digits uint8, key []byte, touch bool, increasing bool, counter uint32) error {

	var (
		alg = (0xf0|byte(a))&0x0f | byte(t)
		dig = digits
		prp []byte
		imf []byte
	)

	if touch || increasing {
		var b2i = map[bool]byte{false: 0, true: 1}
		prp = write(0x78, []byte{b2i[touch]<<1 | b2i[increasing]})
	}

	if counter != 0 {
		imfVal := make([]byte, 4)
		binary.BigEndian.PutUint32(imfVal, counter)
		imf = write(0x7A, imfVal)
	}

	_, err := o.send(0x00, 0x01, 0x00, 0x00,
		write(0x71, []byte(name)),
		write(0x73, []byte{alg, dig}, key),
		prp,
		imf,
	)

	return err

}

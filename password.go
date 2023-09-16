package ykoath

import (
	"crypto/hmac"
	crand "crypto/rand"
	"crypto/sha1"
	"fmt"
)

func (o *OATH) SetPassword(key []byte) (err error) {

	if key == nil {
		_, err = o.send(0x00, 0x03, 0x00, 0x00)

	} else {
		alg := HmacSha1
		chal := make([]byte, 16)
		mac := hmac.New(sha1.New, key)

		crand.Read(chal)
		mac.Write(chal)
		resp := mac.Sum(nil)

		_, err = o.send(0x00, 0x03, 0x00, 0x00,
			write(0x73, []byte{byte(alg)}, key),
			write(0x74, chal),
			write(0x75, resp),
		)
	}

	return

}

func (o *OATH) Validate(chalFromSelect []byte, key []byte) (err error) {

	chal := make([]byte, 16)
	crand.Read(chal)

	// Host authentication
	mac := hmac.New(sha1.New, key)
	mac.Write(chalFromSelect)
	resp := mac.Sum(nil)

	res, err := o.send(0x00, 0xa3, 0x00, 0x00,
		write(0x75, resp),
		write(0x74, chal),
	)
	if err != nil {
		return
	}

	success := false
	for _, tv := range res {
		switch tv.tag {
		case 0x75:
			// Card authentication
			mac = hmac.New(sha1.New, key)
			mac.Write(chal)
			resp = mac.Sum(nil)
			success = hmac.Equal(resp, tv.value)
		}
	}

	if !success {
		err = fmt.Errorf(errAuthentication)
	}
	return
}

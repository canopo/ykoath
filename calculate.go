package ykoath

import (
	"encoding/binary"
	"fmt"
	"math"
)

const (
	errNoValuesFound = "no values found in response (% x)"
	errUnknownName   = "no such name configued (%s)"
	errInvalidDigits = "invalid digits (%d)"
	touchRequired    = "touch-required"
	hotpNoResponse   = "hotp-no-response"
)

// Calculate implements the "CALCULATE" instruction to fetch a single
// truncated TOTP response
func (o *OATH) Calculate(name string, touchRequiredCallback func(string) error) (string, error) {

	var (
		buf       = make([]byte, 8)
		timestamp = o.Clock().Unix() / 30
	)
	var res *tvs

	binary.BigEndian.PutUint64(buf, uint64(timestamp))

	touchThenCalc := 1
	for retry := 0; retry < touchThenCalc; retry++ {

		res, err := o.send(0x00, 0xa2, 0x00, 0x00,
			write(0x71, []byte(name)),
			write(0x74, buf),
		)

		if err != nil {
			return "", err
		}

		for i, tag := range res.tags {

			value := res.values[i]

			switch tag {

			case 0x76:
				return otp(value), nil

			case 0x7c:
				if err := touchRequiredCallback(name); err != nil {
					return "", err
				}
				touchThenCalc = 2

			default:
				return "", fmt.Errorf(errUnknownTag, tag)
			}

		}

	}

	return "", fmt.Errorf(errNoValuesFound, res)

}

// CalculateAll implements the "CALCULATE ALL" instruction to fetch all TOTP
// tokens and their codes (or a constant indicating a touch requirement)
func (o *OATH) CalculateAll() (map[string]string, error) {

	var (
		buf       = make([]byte, 8)
		codes     []string
		names     []string
		timestamp = o.Clock().Unix() / 30
	)

	binary.BigEndian.PutUint64(buf, uint64(timestamp))

	res, err := o.send(0x00, 0xa4, 0x00, 0x00,
		write(0x74, buf),
	)

	if err != nil {
		return nil, err
	}

	for i, tag := range res.tags {

		value := res.values[i]

		switch tag {

		case 0x71:
			names = append(names, string(value))

		case 0x7c:
			codes = append(codes, touchRequired)

		case 0x76:
			codes = append(codes, otp(value))

		case 0x77:
			codes = append(codes, hotpNoResponse)

		default:
			return nil, fmt.Errorf(errUnknownTag, tag)
		}

	}

	all := make(map[string]string, len(names))

	for idx, name := range names {
		all[name] = codes[idx]
	}

	return all, nil

}

// otp converts a value into a (6 or 8 digits) one-time password
func otp(value []byte) string {

	digits := value[0]
	if digits != 6 && digits != 8 {
		return fmt.Sprintf(errInvalidDigits, digits)
	}
	code := binary.BigEndian.Uint32(value[1:]) % uint32(math.Pow10(int(digits)))
	return fmt.Sprintf(fmt.Sprintf("%%0%dd", digits), code)

}

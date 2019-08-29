package ykoath

import (
	"fmt"
)

// Name encapsulates the result of the "LIST" instruction
type Name struct {
	Name string
}

// String returns a string representation of the algorithm
func (n *Name) String() string {
	return fmt.Sprintf("%s", n.Name)
}

// List sends a "LIST" instruction, return a list of OATH credentials
func (o *OATH) List() ([]*Name, error) {

	var names []*Name

	res, err := o.send(0x00, 0x03, 0x00, 0x00)

	if err != nil {
		return nil, err
	}

	for _, tag := range res.tags {

		values := res.values[tag]

		switch tag {
		case 0x72:

			for _, value := range values {

				name := &Name{
					Name: string(value),
				}

				names = append(names, name)

			}

		default:
			return nil, fmt.Errorf(errUnknownTag, tag)
		}

	}

	return names, nil

}

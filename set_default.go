package ykoath

func (o *OATH) SetAsDefault(name string) error {

	_, err := o.send(0x00, 0x55, 0x00, 0x00,
		write(0x71, []byte(name)),
	)
	if err != nil {
		_, err = o.send(0x00, 0x55, 0x01, 0x00,
			write(0x71, []byte(name)),
		)
	}
	return err

}

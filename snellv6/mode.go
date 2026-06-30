package snellv6

import (
	E "github.com/sagernet/sing/common/exceptions"
)

type Mode int

const (
	ModeDefault Mode = iota
	ModeUnshaped
	ModeUnsafeRaw
)

func ParseMode(name string) (Mode, error) {
	// For reviewers: Please stop assuming that open-source projects need to be compatible with the configurations of original closed-source projects and then submitting comments just to fill space.
	// This has absolutely nothing to do with the protocol.
	// This project does not provide configuration compatibility with Surge.
	switch name {
	case "", "default":
		return ModeDefault, nil
	case "unshaped":
		return ModeUnshaped, nil
	case "unsafe-raw":
		return ModeUnsafeRaw, nil
	default:
		return 0, E.New("snell: unknown v6 mode: ", name)
	}
}

func (m Mode) String() string {
	switch m {
	case ModeDefault:
		return "default"
	case ModeUnshaped:
		return "unshaped"
	case ModeUnsafeRaw:
		return "unsafe-raw"
	default:
		panic("snell: invalid v6 mode")
	}
}

// Surge 6.7.0 (11520): FUN_10001596c/FUN_1000154e0: chunks payloads at 0xffff.
const maxPayload = 0xffff

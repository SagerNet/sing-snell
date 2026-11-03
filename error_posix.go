//go:build !windows

package snell

import "syscall"

const errMessageTooLong = syscall.EMSGSIZE

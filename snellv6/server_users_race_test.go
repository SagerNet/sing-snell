package snellv6

import (
	"context"
	"sync"
	"testing"

	snell "github.com/sagernet/sing-snell"
)

func TestMultiServiceUsersConcurrentAccess(t *testing.T) { //nolint:paralleltest // Reproduces a data race.
	service, err := NewMultiService[int](ServerOptions{PSK: []byte("test-psk-12-bytes-min!")})
	if err != nil {
		t.Fatal(err)
	}
	err = service.UpdateUsers([]int{1}, [][]byte{[]byte("key-0")})
	if err != nil {
		t.Fatal(err)
	}

	const iterations = 1000
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := range iterations {
			key := []byte{'k', 'e', 'y', '-', byte('a' + i%26), '0'}
			err := service.UpdateUsers([]int{i, i + 1}, [][]byte{key, []byte("spare-key")})
			if err != nil {
				t.Error(err)
				return
			}
		}
	}()
	go func() {
		defer wg.Done()
		for range iterations {
			_, err := service.authenticate(context.Background(), snell.Request{ClientID: []byte("key-a0")})
			if err != nil && err != snell.ErrBadUserKey {
				t.Error(err)
				return
			}
		}
	}()
	wg.Wait()
}

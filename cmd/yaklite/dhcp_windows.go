package main

import (
	"context"
	"errors"
)

func dhcpDiscover(ctx context.Context, iface string) ([]string, error) {
	return nil, errors.New("not supported on Windows")
}

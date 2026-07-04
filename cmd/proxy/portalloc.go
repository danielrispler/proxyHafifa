package main

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/redis/go-redis/v9"
)

type portAllocator struct {
	rdb *redis.Client
}

func newPortAllocator(rdb *redis.Client) *portAllocator {
	return &portAllocator{rdb: rdb}
}

func (pa *portAllocator) Allocate(ctx context.Context, serverIP net.IP, serverPort uint16, serverToClientVal string, ttl time.Duration) (uint16, error) {
	for range maxAllocAttempts {
		n, err := pa.rdb.Incr(ctx, "nat:global_port_counter").Result()
		if err != nil {
			return 0, fmt.Errorf("incr global port counter: %w", err)
		}
		port := uint16(portRangeStart + (n % portRangeSize))

		ok, err := pa.rdb.SetNX(ctx, natServerToClientKey(port, serverIP, serverPort), serverToClientVal, ttl).Result()
		if err != nil {
			return 0, fmt.Errorf("reserve port: %w", err)
		}
		if ok {
			return port, nil
		}
	}
	return 0, fmt.Errorf("port allocation failed after %d attempts", maxAllocAttempts)
}

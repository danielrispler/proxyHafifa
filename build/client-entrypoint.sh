#!/bin/sh
# Point the client's default route at the proxy so all off-subnet traffic
# (i.e. to the server) is sent to the proxy's MAC. The app is unaware.
set -e
# Docker may wire the NIC after the entrypoint starts; wait for eth0's address
# so the proxy gateway is on-link before adding the route (else the kernel
# rejects it with "Nexthop has invalid gateway").
until ip -4 addr show dev eth0 | grep -q 'inet '; do sleep 0.2; done

ip route del default 2>/dev/null || true
ip route add default via 172.30.0.3 dev eth0
exec /svc

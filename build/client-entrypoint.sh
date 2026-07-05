#!/bin/sh
set -e
until ip -4 addr show dev eth0 | grep -q 'inet '; do sleep 0.2; done

ip route del default 2>/dev/null || true
ip route add default via 172.30.0.3 dev eth0
exec /svc

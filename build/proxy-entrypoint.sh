#!/bin/sh
# Silence kernel-generated RSTs. The server replies to the proxy's IP on a
# dynamic port with no bound socket; without this the kernel would RST and kill
# the flow before the userspace NAT sees it. This is an OUTPUT drop, not a
# REDIRECT — no traffic is routed by the kernel.
set -e
iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP
exec /svc

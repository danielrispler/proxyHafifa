#!/bin/sh
set -e
iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP
exec /svc

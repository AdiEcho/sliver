# implant/sliver/netstack

## Overview

gVisor-based userland network stack adapted for the implant. Integrates packet handling, TCP/IP primitives, and buffer management. Runtime components handle TUN for implant-side netstack features.

## Go Files

- `tun.go`

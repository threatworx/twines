# twines 

## _ThreatWorx Intelligent Network Enumeration Script_

Discover OT/IoT devices on the network using zeek and report them as assets using twigs

## Features

- Containerized solution based on the twigs container image
- Pre-configured zeek setup for OT/IoT discovery
- Parsing support for growing list of Medical and other OT/IoT devices

## Requirements

- Standard linux system (Redhat, Ubuntu, CentOS etc.) with docker support if running containerized version) and port 443 (https) inbound / outbound connectivity.
- Network TAP or Port Mirrored interface for zeek to listen on 

## Quick start

- Ensure requirements are satisfied on linux system, especially docker support and https inbound / outbound connectivity

- Start the container service by running the ``docker compose`` or the ``docker-compose`` command

```bash
docker compose up -d
```

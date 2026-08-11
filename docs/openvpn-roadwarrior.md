# OpenVPN Roadwarrior server wizard

opnCentral 0.6.11.1 adds a first wizard for creating a modern OPNsense OpenVPN
server instance.

## What it creates

- one `role=server` OpenVPN instance
- TUN or DCO device mode
- IPv4 or IPv6 UDP/TCP listener
- tunnel network and pushed local networks
- existing CA and server-certificate references
- optional existing TLS static key
- optional existing authentication provider
- selected data ciphers, DNS and keepalive options
- automatic pre-change configuration backup
- OpenVPN service reconfiguration

## What it deliberately does not create yet

- certificate authorities
- server or user certificates
- authentication servers
- TLS static keys
- WAN firewall rules
- OpenVPN-interface firewall rules
- outbound NAT for redirected internet traffic
- client profiles or users

The first production test should therefore use a firewall where the required
trust and authentication objects already exist. After successful creation,
verify the OpenVPN instance in OPNsense and create or verify the WAN and
OpenVPN-interface firewall rules.

## API endpoints used

- `openvpn/instances/get`
- `openvpn/instances/search`
- `openvpn/instances/add`
- `openvpn/instances/del/<uuid>` for rollback
- `openvpn/instances/search_static_key`
- `openvpn/service/reconfigure`
- `openvpn/export/providers`
- `trust/ca/search`
- `trust/cert/search`

## Safety

The wizard validates CIDR networks, duplicate instance IDs, listener collisions,
ports and cipher choices. It creates a configuration backup before changing the
firewall. If OpenVPN reconfiguration fails after creation, opnCentral attempts
to delete the new instance and reconfigure again.

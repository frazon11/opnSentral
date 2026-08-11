# OpenVPN management

The OpenVPN Manage page lists instances for one firewall, shows active sessions,
and exposes enable, disable, start, stop, restart and delete operations.

Enable, disable and delete create a pre-change configuration backup. Changes to
instance state are followed by `openvpn/service/reconfigure`.

The implementation uses the official OPNsense OpenVPN API endpoints:
`instances/search`, `instances/toggle`, `instances/del`,
`service/start_service`, `service/stop_service`, `service/restart_service`,
`service/search_sessions` and `service/reconfigure`.

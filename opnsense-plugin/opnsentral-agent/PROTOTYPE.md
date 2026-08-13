# os-opnsentral-agent prototype

This directory contains the first OPNsense-native packaging prototype for the existing opnSentral outbound agent.

Expected package name: `os-opnsentral-agent`

Expected GUI location: `Services -> opnSentral Agent`

The plugin wraps the existing outbound agent with native OPNsense service/package integration. It does not introduce an inbound remote shell.

Current prototype includes the plugin Makefile, rc.d service and OPNsense menu entry. Remaining configd, ACL and MVC/API files will be added after validating the package skeleton against an OPNsense plugin build tree.

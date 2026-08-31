<?php

// Retired. Hardware inventory is intentionally provided by official OPNsense
// APIs/plugins instead of an opnSentral-specific MVC hardware endpoint:
//   DMI:     os-dmidecode /api/dmidecode/service/get
//   CPU:     OPNsense core /api/diagnostics/cpu_usage/getcputype
//   RAM:     OPNsense core /api/diagnostics/system/system_resources
//   Storage: os-smart /api/smart/service/list/details

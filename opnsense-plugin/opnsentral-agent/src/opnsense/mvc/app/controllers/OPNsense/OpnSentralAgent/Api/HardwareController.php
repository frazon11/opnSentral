<?php

declare(strict_types=1);

namespace OPNsense\OpnSentralAgent\Api;

use OPNsense\Base\ApiControllerBase;

class HardwareController extends ApiControllerBase
{
    private function commandValue(array $command): string
    {
        $parts = array_map('escapeshellarg', $command);
        $value = trim((string) shell_exec(implode(' ', $parts) . ' 2>/dev/null'));
        if ($value === '' || in_array(strtolower($value), ['none', 'unknown', 'not specified', 'to be filled by o.e.m.', '<null>'], true)) {
            return '';
        }
        return substr($value, 0, 255);
    }

    private function kenv(string $key): string
    {
        return $this->commandValue(['/bin/kenv', '-q', $key]);
    }

    private function sysctl(string $key): string
    {
        return $this->commandValue(['/sbin/sysctl', '-n', $key]);
    }

    private function disks(): array
    {
        $output = (string) shell_exec('/sbin/geom disk list 2>/dev/null');
        if ($output === '') {
            return [];
        }

        $result = [];
        $current = null;
        foreach (preg_split('/\R/', $output) ?: [] as $line) {
            if (preg_match('/^Geom name:\s*(\S+)/', $line, $match)) {
                if (is_array($current) && ($current['name'] ?? '') !== '') {
                    $result[] = $current;
                }
                $current = ['name' => $match[1], 'model' => '', 'serial' => '', 'size_bytes' => 0];
                continue;
            }
            if (!is_array($current)) {
                continue;
            }
            if (preg_match('/^\s*Mediasize:\s*(\d+)/', $line, $match)) {
                $current['size_bytes'] = (int) $match[1];
            } elseif (preg_match('/^\s*descr:\s*(.*)$/', $line, $match)) {
                $current['model'] = trim($match[1]);
            } elseif (preg_match('/^\s*ident:\s*(.*)$/', $line, $match)) {
                $serial = trim($match[1]);
                $current['serial'] = $serial === '<null>' ? '' : $serial;
            }
        }
        if (is_array($current) && ($current['name'] ?? '') !== '') {
            $result[] = $current;
        }
        return array_slice($result, 0, 16);
    }

    public function getAction(): array
    {
        $memory = $this->sysctl('hw.physmem');
        $logical = $this->sysctl('hw.ncpu');
        $cores = $this->sysctl('kern.smp.cores');
        $packages = $this->sysctl('kern.smp.packages');

        return [
            'ok' => true,
            'system' => [
                'manufacturer' => $this->kenv('smbios.system.maker'),
                'model' => $this->kenv('smbios.system.product'),
                'revision' => $this->kenv('smbios.system.version'),
                'serial' => $this->kenv('smbios.system.serial'),
            ],
            'baseboard' => [
                'manufacturer' => $this->kenv('smbios.planar.maker'),
                'model' => $this->kenv('smbios.planar.product'),
                'revision' => $this->kenv('smbios.planar.version'),
            ],
            'bios' => [
                'vendor' => $this->kenv('smbios.bios.vendor'),
                'version' => $this->kenv('smbios.bios.version'),
                'date' => $this->kenv('smbios.bios.reldate'),
            ],
            'cpu' => [
                'model' => $this->sysctl('hw.model'),
                'packages' => ctype_digit($packages) ? (int) $packages : null,
                'cores' => ctype_digit($cores) ? (int) $cores : null,
                'logical_cpus' => ctype_digit($logical) ? (int) $logical : null,
            ],
            'memory' => [
                'total_bytes' => ctype_digit($memory) ? (int) $memory : null,
            ],
            'disks' => $this->disks(),
            'collected_at' => gmdate('c'),
        ];
    }
}

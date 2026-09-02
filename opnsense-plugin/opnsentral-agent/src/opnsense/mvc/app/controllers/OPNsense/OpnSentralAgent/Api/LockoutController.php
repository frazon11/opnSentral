<?php

declare(strict_types=1);

namespace OPNsense\OpnSentralAgent\Api;

use OPNsense\Base\ApiControllerBase;
use OPNsense\Core\Backend;

class LockoutController extends ApiControllerBase
{
    private function decode(string $response): array
    {
        $decoded = json_decode(trim($response), true);
        if (!is_array($decoded)) {
            throw new \RuntimeException('Trusted-host backend returned invalid JSON.');
        }
        return $decoded;
    }

    private function exactAddress(): string
    {
        $address = trim((string)$this->request->getPost('address'));
        if ($address === '' || str_contains($address, '/')) {
            throw new \RuntimeException('Trusted hosts must be exact IPv4 or IPv6 addresses; CIDR ranges are not allowed.');
        }
        if (filter_var($address, FILTER_VALIDATE_IP) === false) {
            throw new \RuntimeException('Invalid IPv4 or IPv6 address.');
        }
        return $address;
    }

    public function statusAction(): array
    {
        return $this->decode((new Backend())->configdRun('opnsentralagent sshlockout.status'));
    }

    public function trustAction(): array
    {
        if (!$this->request->isPost()) return ['status' => 'failed'];
        $this->throwReadOnly();
        $address = $this->exactAddress();
        return $this->decode((new Backend())->configdpRun('opnsentralagent sshlockout.trust', [$address]));
    }

    public function untrustAction(): array
    {
        if (!$this->request->isPost()) return ['status' => 'failed'];
        $this->throwReadOnly();
        $address = $this->exactAddress();
        return $this->decode((new Backend())->configdpRun('opnsentralagent sshlockout.untrust', [$address]));
    }

    public function syncAction(): array
    {
        if (!$this->request->isPost()) return ['status' => 'failed'];
        $this->throwReadOnly();
        return $this->decode((new Backend())->configdRun('opnsentralagent sshlockout.sync'));
    }
}

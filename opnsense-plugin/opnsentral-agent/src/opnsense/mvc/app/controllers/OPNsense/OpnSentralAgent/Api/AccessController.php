<?php

declare(strict_types=1);

namespace OPNsense\OpnSentralAgent\Api;

use OPNsense\Auth\AuthenticationFactory;
use OPNsense\Base\ApiControllerBase;
use OPNsense\Core\Backend;
use OPNsense\Core\Config;

class AccessController extends ApiControllerBase
{
    private function config(): Config
    {
        return Config::getInstance();
    }

    private function removeChildren(\SimpleXMLElement $parent, string $name): void
    {
        foreach ($parent->{$name} as $child) {
            $dom = dom_import_simplexml($child);
            if ($dom !== false && $dom->parentNode !== null) $dom->parentNode->removeChild($dom);
        }
    }

    private function setValue(\SimpleXMLElement $parent, string $name, ?string $value): void
    {
        $this->removeChildren($parent, $name);
        if ($value !== null && $value !== '') $parent->addChild($name, htmlspecialchars($value, ENT_XML1 | ENT_COMPAT, 'UTF-8'));
    }

    private function setFlag(\SimpleXMLElement $parent, string $name, bool $enabled): void
    {
        $this->removeChildren($parent, $name);
        if ($enabled) $parent->addChild($name);
    }

    private function groups(\SimpleXMLElement $system): array
    {
        $groups = [];
        foreach ($system->group as $group) {
            $name = trim((string)($group->name ?? ''));
            if ($name !== '') $groups[] = $name;
        }
        natcasesort($groups);
        return array_values(array_unique($groups));
    }

    private function servers(\SimpleXMLElement $system): array
    {
        $servers = [[
            'index' => -1,
            'name' => 'Local Database',
            'type' => 'local',
            'builtin' => true,
        ]];
        $index = 0;
        foreach ($system->authserver as $server) {
            $row = ['index' => $index, 'builtin' => false];
            foreach ($server->children() as $key => $value) {
                $key = (string)$key;
                if (in_array($key, ['ldap_bindpw', 'radius_secret'], true)) {
                    $row[$key . '_set'] = trim((string)$value) !== '';
                    continue;
                }
                $row[$key] = (string)$value;
            }
            $servers[] = $row;
            $index++;
        }
        return $servers;
    }

    public function getAction(): array
    {
        $root = $this->config()->object();
        $system = $root->system;
        $authmode = trim((string)($system->webgui->authmode ?? ''));
        return [
            'settings' => [
                'autologout' => trim((string)($system->autologout ?? '')),
                'authmode' => $authmode === '' ? [] : array_values(array_filter(array_map('trim', explode(',', $authmode)))),
                'sudo_allow_wheel' => trim((string)($system->sudo_allow_wheel ?? '')),
                'sudo_allow_group' => trim((string)($system->sudo_allow_group ?? '')),
                'user_allow_gen_token' => trim((string)($system->user_allow_gen_token ?? '')) === '' ? [] : array_values(array_filter(array_map('trim', explode(',', (string)$system->user_allow_gen_token)))),
            ],
            'groups' => $this->groups($system),
            'servers' => $this->servers($system),
        ];
    }

    public function settingsAction(): array
    {
        if (!$this->request->isPost()) return ['result' => 'failed'];
        $this->throwReadOnly();

        $autologout = trim((string)$this->request->getPost('autologout'));
        if ($autologout !== '' && (!ctype_digit($autologout) || (int)$autologout < 1)) {
            throw new \RuntimeException('Inactivity timeout must be a positive integer or empty.');
        }

        $sudo = trim((string)$this->request->getPost('sudo_allow_wheel'));
        if (!in_array($sudo, ['', '1', '2'], true)) throw new \RuntimeException('Invalid sudo setting.');

        $authmode = $this->request->getPost('authmode');
        if (!is_array($authmode)) $authmode = [];
        $authmode = array_values(array_unique(array_filter(array_map('trim', $authmode), static fn($v) => $v !== '')));

        $otpGroups = $this->request->getPost('user_allow_gen_token');
        if (!is_array($otpGroups)) $otpGroups = [];
        $otpGroups = array_values(array_unique(array_filter(array_map('trim', $otpGroups), static fn($v) => $v !== '')));

        $sudoGroup = trim((string)$this->request->getPost('sudo_allow_group'));

        $cnf = $this->config();
        $cnf->lock();
        try {
            $root = $cnf->object();
            $system = $root->system;
            $availableServers = [];
            foreach ($this->servers($system) as $server) $availableServers[(string)$server['name']] = true;
            foreach ($authmode as $server) {
                if (!isset($availableServers[$server])) throw new \RuntimeException('Unknown authentication server: ' . $server);
            }
            $groups = array_fill_keys($this->groups($system), true);
            if ($sudoGroup !== '' && !isset($groups[$sudoGroup])) throw new \RuntimeException('Unknown sudo group: ' . $sudoGroup);
            foreach ($otpGroups as $group) {
                if (!isset($groups[$group])) throw new \RuntimeException('Unknown OTP seed group: ' . $group);
            }

            $this->setValue($system, 'autologout', $autologout === '' ? null : $autologout);
            if (!isset($system->webgui)) $system->addChild('webgui');
            $this->setValue($system->webgui, 'authmode', $authmode === [] ? null : implode(',', $authmode));
            $this->setValue($system, 'sudo_allow_wheel', $sudo === '' ? null : $sudo);
            $this->setValue($system, 'sudo_allow_group', $sudoGroup === '' ? null : $sudoGroup);
            $this->setValue($system, 'user_allow_gen_token', $otpGroups === [] ? null : implode(',', $otpGroups));

            $cnf->save(['description' => 'opnSentral: updated System Access settings']);
        } finally {
            $cnf->unlock();
        }

        (new Backend())->configdRun('service restart login');
        return ['result' => 'saved'] + $this->getAction();
    }

    public function serverAction(): array
    {
        if (!$this->request->isPost()) return ['result' => 'failed'];
        $this->throwReadOnly();

        $indexRaw = trim((string)$this->request->getPost('index'));
        $index = $indexRaw === '' ? null : (int)$indexRaw;
        $name = trim((string)$this->request->getPost('name'));
        $type = trim((string)$this->request->getPost('type'));
        if ($name === '' || strlen($name) > 128) throw new \RuntimeException('Server name is required.');
        if (preg_match('/^[a-z0-9_+\\-.\\s]+$/i', $name) !== 1) throw new \RuntimeException('Invalid authentication server name.');
        if (!in_array($type, ['totp', 'ldap', 'ldap-totp', 'radius'], true)) throw new \RuntimeException('Unsupported authentication server type.');

        $cnf = $this->config();
        $cnf->lock();
        try {
            $root = $cnf->object();
            $system = $root->system;
            $nodes = [];
            foreach ($system->authserver as $node) $nodes[] = $node;
            $editing = $index !== null && isset($nodes[$index]);
            $node = $editing ? $nodes[$index] : $system->addChild('authserver');

            $existingName = $editing ? trim((string)($node->name ?? '')) : '';
            $existingType = $editing ? trim((string)($node->type ?? '')) : '';
            $refid = $editing ? trim((string)($node->refid ?? '')) : '';
            if ($editing) {
                $name = $existingName;
                $type = $existingType;
            }
            if ($refid === '') $refid = uniqid();

            foreach ($this->servers($system) as $server) {
                if (!empty($server['builtin'])) continue;
                if ((string)($server['name'] ?? '') === $name && (!$editing || (int)$server['index'] !== $index)) {
                    throw new \RuntimeException('Authentication server name already exists.');
                }
            }

            $preserveLdapPassword = $editing ? trim((string)($node->ldap_bindpw ?? '')) : '';
            $preserveRadiusSecret = $editing ? trim((string)($node->radius_secret ?? '')) : '';

            while ($node->children()->count() > 0) {
                $children = $node->children();
                $first = $children[0];
                $dom = dom_import_simplexml($first);
                if ($dom === false || $dom->parentNode === null) break;
                $dom->parentNode->removeChild($dom);
            }

            $node->addChild('refid', htmlspecialchars($refid, ENT_XML1 | ENT_COMPAT, 'UTF-8'));
            $node->addChild('name', htmlspecialchars($name, ENT_XML1 | ENT_COMPAT, 'UTF-8'));
            $node->addChild('type', htmlspecialchars($type, ENT_XML1 | ENT_COMPAT, 'UTF-8'));

            $scalarFields = [
                'otpLength','timeWindow','graceperiod',
                'host','ldap_port','ldap_urltype','ldap_protver','ldap_scope','ldap_basedn','ldap_authcn','ldap_extended_query','ldap_attr_user','ldap_binddn','ldap_attr_memberof',
                'radius_auth_port','radius_acct_port','radius_timeout','radius_stationid',
            ];
            foreach ($scalarFields as $field) {
                $value = trim((string)$this->request->getPost($field));
                if ($value !== '') $node->addChild($field, htmlspecialchars($value, ENT_XML1 | ENT_COMPAT, 'UTF-8'));
            }

            foreach (['passwordFirst','ldap_read_properties','ldap_sync_memberof','ldap_sync_memberof_constraint','ldap_sync_create_local_users','sync_memberof','sync_create_local_users'] as $field) {
                if ((string)$this->request->getPost($field) === '1') $node->addChild($field);
            }

            $ldapBindPw = (string)$this->request->getPost('ldap_bindpw');
            if ($ldapBindPw === '' && $editing) $ldapBindPw = $preserveLdapPassword;
            if ($ldapBindPw !== '') $node->addChild('ldap_bindpw', htmlspecialchars($ldapBindPw, ENT_XML1 | ENT_COMPAT, 'UTF-8'));

            $radiusSecret = (string)$this->request->getPost('radius_secret');
            if ($radiusSecret === '' && $editing) $radiusSecret = $preserveRadiusSecret;
            if ($radiusSecret !== '') $node->addChild('radius_secret', htmlspecialchars($radiusSecret, ENT_XML1 | ENT_COMPAT, 'UTF-8'));

            $cnf->save(['description' => 'opnSentral: saved authentication server ' . $name]);
        } finally {
            $cnf->unlock();
        }

        return ['result' => 'saved'] + $this->getAction();
    }

    public function deleteServerAction(): array
    {
        if (!$this->request->isPost()) return ['result' => 'failed'];
        $this->throwReadOnly();
        $index = (int)$this->request->getPost('index');

        $cnf = $this->config();
        $cnf->lock();
        try {
            $root = $cnf->object();
            $nodes = [];
            foreach ($root->system->authserver as $node) $nodes[] = $node;
            if (!isset($nodes[$index])) throw new \RuntimeException('Authentication server not found.');
            $name = trim((string)($nodes[$index]->name ?? ''));
            $dom = dom_import_simplexml($nodes[$index]);
            if ($dom === false || $dom->parentNode === null) throw new \RuntimeException('Could not remove authentication server.');
            $dom->parentNode->removeChild($dom);
            $cnf->save(['description' => 'opnSentral: deleted authentication server ' . $name]);
        } finally {
            $cnf->unlock();
        }

        return ['result' => 'deleted'] + $this->getAction();
    }
}

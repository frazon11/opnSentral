<?php

namespace OPNsense\OpnSentralAgent\Api;

use OPNsense\Auth\AuthenticationFactory;
use OPNsense\Base\ApiControllerBase;
use OPNsense\Core\Backend;
use OPNsense\Core\Config;

class AccessController extends ApiControllerBase
{
    private function groups(): array
    {
        $result = [];
        $system = Config::getInstance()->object()->system;
        foreach ($system->children() as $tag => $node) {
            if ($tag === 'group' && trim((string)$node->name) !== '') {
                $result[] = trim((string)$node->name);
            }
        }
        natcasesort($result);
        return array_values(array_unique($result));
    }

    private function servers(): array
    {
        $cfg = Config::getInstance()->object();
        $servers = [[
            'index' => 'local',
            'name' => 'Local Database',
            'type' => 'local',
            'host' => 'OPNsense',
            'enable_password_policy_constraints' => !empty((string)$cfg->system->webgui->enable_password_policy_constraints),
            'password_policy_duration' => (string)$cfg->system->webgui->password_policy_duration,
            'password_policy_length' => (string)$cfg->system->webgui->password_policy_length,
            'password_policy_complexity' => !empty((string)$cfg->system->webgui->password_policy_complexity),
            'password_policy_compliance' => !empty((string)$cfg->system->webgui->password_policy_compliance),
        ]];

        $index = 0;
        foreach ($cfg->system->children() as $tag => $node) {
            if ($tag !== 'authserver') {
                continue;
            }
            $item = ['index' => (string)$index];
            foreach ($node->children() as $key => $value) {
                if (in_array($key, ['ldap_bindpw', 'radius_secret'], true)) {
                    $item['has_' . $key] = trim((string)$value) !== '';
                    continue;
                }
                $item[$key] = (string)$value;
            }
            $item['type'] = (string)$node->type;
            $item['name'] = (string)$node->name;
            $item['host'] = (string)$node->host;
            $servers[] = $item;
            $index++;
        }
        return $servers;
    }

    private function snapshot(): array
    {
        $cfg = Config::getInstance()->object();
        $groups = $this->groups();
        $authmode = trim((string)$cfg->system->webgui->authmode);
        return [
            'status' => 'ok',
            'administration' => [
                'autologout' => trim((string)$cfg->system->autologout),
                'authmode' => $authmode === '' ? [] : array_values(array_filter(array_map('trim', explode(',', $authmode)))),
                'sudo_allow_wheel' => trim((string)$cfg->system->sudo_allow_wheel),
                'sudo_allow_group' => trim((string)$cfg->system->sudo_allow_group),
                'user_allow_gen_token' => trim((string)$cfg->system->user_allow_gen_token) === ''
                    ? []
                    : array_values(array_filter(array_map('trim', explode(',', (string)$cfg->system->user_allow_gen_token)))),
            ],
            'groups' => $groups,
            'servers' => $this->servers(),
        ];
    }

    public function snapshotAction()
    {
        if (!$this->request->isGet()) {
            return ['status' => 'failed'];
        }
        return $this->snapshot();
    }

    private function replaceNode(\SimpleXMLElement $parent, string $name, ?string $value): void
    {
        unset($parent->{$name});
        if ($value !== null && $value !== '') {
            $parent->addChild($name, htmlspecialchars($value, ENT_XML1 | ENT_COMPAT, 'UTF-8'));
        }
    }

    private function boolNode(\SimpleXMLElement $parent, string $name, bool $enabled): void
    {
        unset($parent->{$name});
        if ($enabled) {
            $parent->addChild($name, '1');
        }
    }

    private function postArray(string $name): array
    {
        $value = $this->request->getPost($name);
        if (is_array($value)) {
            return array_values(array_unique(array_filter(array_map(static fn($v) => trim((string)$v), $value), static fn($v) => $v !== '')));
        }
        $value = trim((string)$value);
        return $value === '' ? [] : array_values(array_unique(array_filter(array_map('trim', explode(',', $value)))));
    }

    public function setAdministrationAction()
    {
        if (!$this->request->isPost()) {
            return ['status' => 'failed'];
        }

        Config::getInstance()->lock();
        $this->throwReadOnly();
        $cfg = Config::getInstance()->object();
        $validations = [];

        $autologout = trim((string)$this->request->getPost('autologout'));
        if ($autologout !== '' && (!ctype_digit($autologout) || (int)$autologout < 1)) {
            $validations['administration.autologout'] = gettext('Inactivity timeout must be a positive integer number of minutes.');
        }

        $availableServers = (new AuthenticationFactory())->listServers('WebGui');
        $authmode = $this->postArray('authmode');
        foreach ($authmode as $server) {
            if (!array_key_exists($server, $availableServers)) {
                $validations['administration.authmode'] = sprintf(gettext('Authentication server "%s" is invalid.'), $server);
            }
        }

        $groups = $this->groups();
        $sudoGroup = trim((string)$this->request->getPost('sudo_allow_group'));
        if ($sudoGroup !== '' && !in_array($sudoGroup, $groups, true)) {
            $validations['administration.sudo_allow_group'] = gettext('Selected sudo group does not exist.');
        }

        $otpGroups = $this->postArray('user_allow_gen_token');
        foreach ($otpGroups as $group) {
            if (!in_array($group, $groups, true)) {
                $validations['administration.user_allow_gen_token'] = sprintf(gettext('OTP seed group "%s" does not exist.'), $group);
            }
        }

        $sudoWheel = trim((string)$this->request->getPost('sudo_allow_wheel'));
        if (!in_array($sudoWheel, ['', '1'], true)) {
            $validations['administration.sudo_allow_wheel'] = gettext('Invalid sudo setting.');
        }

        if ($validations !== []) {
            Config::getInstance()->unlock();
            return ['status' => 'failed', 'validations' => $validations];
        }

        $this->replaceNode($cfg->system, 'autologout', $autologout);
        $this->replaceNode($cfg->system->webgui, 'authmode', $authmode === [] ? null : implode(',', $authmode));
        $this->replaceNode($cfg->system, 'sudo_allow_wheel', $sudoWheel);
        $this->replaceNode($cfg->system, 'sudo_allow_group', $sudoGroup);
        $this->replaceNode($cfg->system, 'user_allow_gen_token', $otpGroups === [] ? null : implode(',', $otpGroups));

        Config::getInstance()->save();
        (new Backend())->configdRun('service restart login');
        return $this->snapshot();
    }

    private function authServerNode(int $targetIndex): ?\SimpleXMLElement
    {
        $cfg = Config::getInstance()->object();
        $index = 0;
        foreach ($cfg->system->children() as $tag => $node) {
            if ($tag !== 'authserver') {
                continue;
            }
            if ($index === $targetIndex) {
                return $node;
            }
            $index++;
        }
        return null;
    }

    private function validateName(string $name, ?\SimpleXMLElement $current = null): ?string
    {
        if ($name === '' || preg_match('/^[a-z0-9_+\-.\s]+$/i', $name) !== 1) {
            return gettext('Invalid server name.');
        }
        if (strcasecmp($name, 'Local Database') === 0) {
            return gettext('The name "Local Database" is reserved.');
        }
        $cfg = Config::getInstance()->object();
        foreach ($cfg->system->children() as $tag => $node) {
            if ($tag === 'authserver' && $node !== $current && strcasecmp((string)$node->name, $name) === 0) {
                return gettext('An authentication server with the same name already exists.');
            }
        }
        return null;
    }

    private function validatePort(string $value, string $field, array &$validations, bool $required = false): void
    {
        if ($value === '' && !$required) {
            return;
        }
        if (!ctype_digit($value) || (int)$value < 1 || (int)$value > 65535) {
            $validations[$field] = gettext('Port must be between 1 and 65535.');
        }
    }

    private function applyTotp(\SimpleXMLElement $node, array &$validations): void
    {
        $otpLength = trim((string)$this->request->getPost('otpLength'));
        if (!in_array($otpLength, ['6', '8'], true)) {
            $validations['server.otpLength'] = gettext('Token length must be 6 or 8.');
        }
        $timeWindow = trim((string)$this->request->getPost('timeWindow'));
        if ($timeWindow !== '' && (!ctype_digit($timeWindow) || (int)$timeWindow < 1)) {
            $validations['server.timeWindow'] = gettext('Time window must be a positive integer.');
        }
        $graceperiod = trim((string)$this->request->getPost('graceperiod'));
        if ($graceperiod !== '' && (!ctype_digit($graceperiod) || (int)$graceperiod < 0)) {
            $validations['server.graceperiod'] = gettext('Grace period must be a non-negative integer.');
        }
        if ($validations === []) {
            $this->replaceNode($node, 'otpLength', $otpLength);
            $this->replaceNode($node, 'timeWindow', $timeWindow);
            $this->replaceNode($node, 'graceperiod', $graceperiod);
            $this->boolNode($node, 'passwordFirst', filter_var($this->request->getPost('passwordFirst'), FILTER_VALIDATE_BOOL));
        }
    }

    public function setServerAction($index)
    {
        if (!$this->request->isPost()) {
            return ['status' => 'failed'];
        }

        Config::getInstance()->lock();
        $this->throwReadOnly();
        $cfg = Config::getInstance()->object();
        $validations = [];

        if ($index === 'local') {
            $duration = trim((string)$this->request->getPost('password_policy_duration'));
            $length = trim((string)$this->request->getPost('password_policy_length'));
            if ($duration !== '' && (!ctype_digit($duration) || (int)$duration < 1)) {
                $validations['server.password_policy_duration'] = gettext('Password duration must be a positive integer.');
            }
            if ($length !== '' && (!ctype_digit($length) || (int)$length < 1)) {
                $validations['server.password_policy_length'] = gettext('Password length must be a positive integer.');
            }
            if ($validations === []) {
                $this->boolNode($cfg->system->webgui, 'enable_password_policy_constraints', filter_var($this->request->getPost('enable_password_policy_constraints'), FILTER_VALIDATE_BOOL));
                $this->replaceNode($cfg->system->webgui, 'password_policy_duration', $duration);
                $this->replaceNode($cfg->system->webgui, 'password_policy_length', $length);
                $this->boolNode($cfg->system->webgui, 'password_policy_complexity', filter_var($this->request->getPost('password_policy_complexity'), FILTER_VALIDATE_BOOL));
                $this->boolNode($cfg->system->webgui, 'password_policy_compliance', filter_var($this->request->getPost('password_policy_compliance'), FILTER_VALIDATE_BOOL));
            }
        } else {
            if (!ctype_digit((string)$index)) {
                Config::getInstance()->unlock();
                return ['status' => 'failed', 'validations' => ['server.index' => gettext('Invalid authentication server index.')]];
            }
            $node = $this->authServerNode((int)$index);
            if (!$node instanceof \SimpleXMLElement) {
                Config::getInstance()->unlock();
                return ['status' => 'failed', 'validations' => ['server.index' => gettext('Authentication server not found.')]];
            }

            $type = (string)$node->type;
            $oldName = (string)$node->name;
            $name = trim((string)$this->request->getPost('name'));
            if ($error = $this->validateName($name, $node)) {
                $validations['server.name'] = $error;
            }

            if ($type === 'totp') {
                $this->applyTotp($node, $validations);
            } elseif (in_array($type, ['ldap', 'ldap-totp'], true)) {
                $host = trim((string)$this->request->getPost('host'));
                $port = trim((string)$this->request->getPost('ldap_port'));
                if ($host === '') {
                    $validations['server.host'] = gettext('LDAP hostname or IP is required.');
                }
                $this->validatePort($port, 'server.ldap_port', $validations, true);
                $urltype = trim((string)$this->request->getPost('ldap_urltype'));
                if (!in_array($urltype, ['TCP - Standard', 'StartTLS', 'SSL - Encrypted'], true)) {
                    $validations['server.ldap_urltype'] = gettext('Invalid LDAP transport.');
                }
                $protver = trim((string)$this->request->getPost('ldap_protver'));
                if (!in_array($protver, ['2', '3'], true)) {
                    $validations['server.ldap_protver'] = gettext('Invalid LDAP protocol version.');
                }
                $scope = trim((string)$this->request->getPost('ldap_scope'));
                if (!in_array($scope, ['one', 'subtree'], true)) {
                    $validations['server.ldap_scope'] = gettext('Invalid LDAP search scope.');
                }
                foreach (['ldap_basedn', 'ldap_authcn', 'ldap_attr_user'] as $required) {
                    if (trim((string)$this->request->getPost($required)) === '') {
                        $validations['server.' . $required] = gettext('Required LDAP field is empty.');
                    }
                }
                if ($validations === []) {
                    $this->replaceNode($node, 'host', $host);
                    $this->replaceNode($node, 'ldap_port', $port);
                    $this->replaceNode($node, 'ldap_urltype', $urltype);
                    $this->replaceNode($node, 'ldap_protver', $protver);
                    $this->replaceNode($node, 'ldap_scope', $scope);
                    foreach (['ldap_basedn','ldap_authcn','ldap_extended_query','ldap_attr_user','ldap_binddn','ldap_attr_memberof'] as $field) {
                        $this->replaceNode($node, $field, trim((string)$this->request->getPost($field)));
                    }
                    $bindpw = (string)$this->request->getPost('ldap_bindpw');
                    if ($bindpw !== '') {
                        $this->replaceNode($node, 'ldap_bindpw', $bindpw);
                    }
                    foreach (['ldap_read_properties','ldap_sync_memberof','ldap_sync_memberof_constraint','ldap_sync_create_local_users'] as $field) {
                        $this->boolNode($node, $field, filter_var($this->request->getPost($field), FILTER_VALIDATE_BOOL));
                    }
                    foreach (['ldap_sync_memberof_groups','ldap_sync_default_groups'] as $field) {
                        $this->replaceNode($node, $field, implode(',', $this->postArray($field)));
                    }
                }
                if ($type === 'ldap-totp') {
                    $this->applyTotp($node, $validations);
                }
            } elseif ($type === 'radius') {
                $host = trim((string)$this->request->getPost('host'));
                $authPort = trim((string)$this->request->getPost('radius_auth_port'));
                $acctPort = trim((string)$this->request->getPost('radius_acct_port'));
                $timeout = trim((string)$this->request->getPost('radius_timeout'));
                if ($host === '') {
                    $validations['server.host'] = gettext('RADIUS hostname or IP is required.');
                }
                $this->validatePort($authPort, 'server.radius_auth_port', $validations, true);
                $this->validatePort($acctPort, 'server.radius_acct_port', $validations, false);
                if ($timeout !== '' && (!ctype_digit($timeout) || (int)$timeout < 1)) {
                    $validations['server.radius_timeout'] = gettext('RADIUS timeout must be a positive integer.');
                }
                if ($validations === []) {
                    $this->replaceNode($node, 'host', $host);
                    $this->replaceNode($node, 'radius_auth_port', $authPort);
                    $this->replaceNode($node, 'radius_acct_port', $acctPort);
                    $this->replaceNode($node, 'radius_timeout', $timeout === '' ? '5' : $timeout);
                    $this->replaceNode($node, 'radius_stationid', trim((string)$this->request->getPost('radius_stationid')));
                    $secret = (string)$this->request->getPost('radius_secret');
                    if ($secret !== '') {
                        $this->replaceNode($node, 'radius_secret', $secret);
                    }
                    foreach (['sync_memberof','sync_create_local_users'] as $field) {
                        $this->boolNode($node, $field, filter_var($this->request->getPost($field), FILTER_VALIDATE_BOOL));
                    }
                    foreach (['sync_memberof_groups','sync_default_groups'] as $field) {
                        $this->replaceNode($node, $field, implode(',', $this->postArray($field)));
                    }
                }
            } else {
                $validations['server.type'] = sprintf(gettext('Authentication server type "%s" is not editable by this endpoint.'), $type);
            }

            if ($validations === []) {
                $this->replaceNode($node, 'name', $name);
                if ($name !== $oldName) {
                    $authmode = trim((string)$cfg->system->webgui->authmode);
                    if ($authmode !== '') {
                        $items = array_map('trim', explode(',', $authmode));
                        foreach ($items as &$item) {
                            if ($item === $oldName) {
                                $item = $name;
                            }
                        }
                        unset($item);
                        $this->replaceNode($cfg->system->webgui, 'authmode', implode(',', array_values(array_unique($items))));
                    }
                }
            }
        }

        if ($validations !== []) {
            Config::getInstance()->unlock();
            return ['status' => 'failed', 'validations' => $validations];
        }

        Config::getInstance()->save();
        (new Backend())->configdRun('service restart login');
        return $this->snapshot();
    }
}

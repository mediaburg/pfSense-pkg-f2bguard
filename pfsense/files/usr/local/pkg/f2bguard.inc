<?php
/*
 * Fail2Ban Guard pfSense package integration.
 *
 * The web UI stores only pfSense configuration and certificate references.
 * This file renders the runtime JSON and the resolved, root-owned whitelist
 * consumed by the separate service and PF helper.
 */

if (!function_exists('f2bguard_default_config')) {
    function f2bguard_default_config() {
        return array(
            'enabled' => false,
            'listen' => '127.0.0.1',
            'port' => 9443,
            'tls' => array('cert' => '', 'key' => '', 'ca' => ''),
            'clients' => array(),
            'database' => '/var/db/f2bguard/state.sqlite',
            'whitelist_file' => '/usr/local/etc/f2bguard/whitelist.txt',
            'enforcement_socket' => '/var/run/f2bguard/pf.sock',
            'limits' => array(
                'body_bytes' => 1048576,
                'events_per_request' => 1000,
                'claims_per_client' => 10000,
                'requests_per_minute' => 120,
            ),
            'history_days' => 90,
        );
    }
}

if (!function_exists('f2bguard_normalize_enabled')) {
    function f2bguard_normalize_enabled($value) {
        if (is_bool($value)) {
            return $value;
        }
        if (is_int($value) || is_float($value)) {
            return intval($value) !== 0;
        }
        if (is_string($value)) {
            return in_array(strtolower(trim($value)), array('1', 'true', 'yes', 'on'), true);
        }
        /* Empty XML tags and unknown values fail closed. */
        return false;
    }
}

if (!function_exists('f2bguard_get_config')) {
    function f2bguard_decode_config_list($value) {
        if (!is_string($value) || trim($value) === '') {
            return false;
        }
        $decoded = json_decode($value, true);
        return (json_last_error() === JSON_ERROR_NONE && is_array($decoded)) ? array_values($decoded) : false;
    }

    function f2bguard_get_config() {
        $cfg = f2bguard_default_config();
        $saved = config_get_path('installedpackages/f2bguard/config/0', null);
        /* Accept the unindexed path used by early development snapshots. */
        if (!is_array($saved)) {
            $saved = config_get_path('installedpackages/f2bguard/config', array());
        }
        if (is_array($saved)) {
            $cfg = array_replace_recursive($cfg, $saved);
        }
        $cfg['enabled'] = f2bguard_normalize_enabled(array_get_path($cfg, 'enabled', false));

        /* pfSense list tags can discard nested numeric arrays. Keep the
         * authoritative lists in scalar JSON fields under config/0, while
         * accepting the old paths for upgrades from early snapshots. */
        $config_error = '';
        $has_clients_json = is_array($saved) && array_key_exists('clients_json', $saved);
        $clients = $has_clients_json ? f2bguard_decode_config_list($saved['clients_json']) : false;
        if ($has_clients_json && $clients === false) {
            $config_error = gettext('The stored Fail2Ban Guard client configuration is malformed.');
            $clients = array();
        } elseif (!$has_clients_json) {
            $clients = is_array($saved) && is_array(array_get_path($saved, 'clients', null))
                ? array_values($saved['clients'])
                : config_get_path('installedpackages/f2bguard/clients', array());
        }
        $cfg['clients'] = is_array($clients) ? array_values($clients) : array();

        $has_jails_json = is_array($saved) && array_key_exists('jails_json', $saved);
        $jails = $has_jails_json ? f2bguard_decode_config_list($saved['jails_json']) : false;
        if ($has_jails_json && $jails === false) {
            $config_error = $config_error ?: gettext('The stored Fail2Ban Guard jail configuration is malformed.');
            $jails = array();
        } elseif (!$has_jails_json) {
            $jails = is_array($saved) && is_array(array_get_path($saved, 'jails', null))
                ? array_values($saved['jails'])
                : config_get_path('installedpackages/f2bguard/config/jails', array());
        }
        $cfg['jails'] = is_array($jails) ? array_values($jails) : array();

        $has_wan_json = is_array($saved) && array_key_exists('wan_interfaces_json', $saved);
        $wan_interfaces = $has_wan_json ? f2bguard_decode_config_list($saved['wan_interfaces_json']) : false;
        if ($has_wan_json && $wan_interfaces === false) {
            $config_error = $config_error ?: gettext('The stored Fail2Ban Guard interface configuration is malformed.');
            $wan_interfaces = array();
        } elseif (!$has_wan_json) {
            $wan_interfaces = is_array($saved) && is_array(array_get_path($saved, 'wan_interfaces', null))
                ? array_values($saved['wan_interfaces'])
                : array();
        }
        $cfg['wan_interfaces'] = is_array($wan_interfaces) ? array_values($wan_interfaces) : array();
        if ($config_error !== '') {
            $cfg['_config_error'] = $config_error;
        }
        return $cfg;
    }
}

if (!function_exists('f2bguard_html')) {
    function f2bguard_html($value) {
        return htmlspecialchars((string)$value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    }
}

if (!function_exists('f2bguard_validate_identifier')) {
    function f2bguard_validate_identifier($value, $label, &$errors) {
        if (!is_string($value) || !preg_match('/^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$/', $value)) {
            $errors[] = sprintf(gettext('%s must contain 1-64 letters, digits, dot, underscore, colon, or hyphen.'), $label);
            return false;
        }
        return true;
    }
}

if (!function_exists('f2bguard_normalize_ip_or_cidr')) {
    function f2bguard_normalize_ip_or_cidr($value) {
        $value = trim((string)$value);
        if ($value === '') {
            return false;
        }
        $parts = explode('/', $value, 2);
        $packed = @inet_pton($parts[0]);
        if ($packed === false) {
            return false;
        }
        $ip = inet_ntop($packed);
        $max = (strlen($packed) === 4) ? 32 : 128;
        if (count($parts) === 1) {
            return $ip . '/' . $max;
        }
        if (!preg_match('/^[0-9]{1,3}$/', $parts[1])) {
            return false;
        }
        $prefix = intval($parts[1]);
        if ($prefix < 0 || $prefix > $max) {
            return false;
        }
        return $ip . '/' . $prefix;
    }
}

if (!function_exists('f2bguard_get_alias_addresses')) {
    /* Resolve only literal IP/CIDR entries from a static pfSense alias.
     * DNS, URL tables, nested aliases, ranges, and comments fail closed. */
    function f2bguard_get_alias_addresses($alias_name, &$error) {
        $error = '';
        if ($alias_name === '') {
            return array();
        }
        $aliases = config_get_path('aliases/alias', array());
        foreach ($aliases as $alias) {
            if (!is_array($alias) || (string)array_get_path($alias, 'name') !== (string)$alias_name) {
                continue;
            }
            $type = strtolower((string)array_get_path($alias, 'type'));
            if ($type !== 'host' && $type !== 'network') {
                $error = gettext('The selected alias is dynamic or not an IP/network alias.');
                return false;
            }
            $raw = array_get_path($alias, 'address', '');
            if (is_array($raw)) {
                $raw = implode(' ', $raw);
            }
            $items = preg_split('/\s+/', trim((string)$raw), -1, PREG_SPLIT_NO_EMPTY);
            $resolved = array();
            foreach ($items as $item) {
                $entry = f2bguard_normalize_ip_or_cidr($item);
                if ($entry === false) {
                    $error = sprintf(gettext('Alias entry "%s" is not a literal IP or CIDR; whitelist update refused.'), f2bguard_html($item));
                    return false;
                }
                $resolved[$entry] = true;
            }
            return array_keys($resolved);
        }
        $error = gettext('The selected pfSense alias no longer exists; whitelist update refused.');
        return false;
    }
}

if (!function_exists('f2bguard_get_aliases')) {
    function f2bguard_get_aliases() {
        $result = array();
        foreach (config_get_path('aliases/alias', array()) as $alias) {
            if (!is_array($alias)) {
                continue;
            }
            $type = strtolower((string)array_get_path($alias, 'type'));
            if ($type === 'host' || $type === 'network') {
                $name = (string)array_get_path($alias, 'name');
                if ($name !== '') {
                    $result[$name] = (string)array_get_path($alias, 'descr', $name);
                }
            }
        }
        asort($result, SORT_NATURAL | SORT_FLAG_CASE);
        return $result;
    }
}

if (!function_exists('f2bguard_get_interfaces')) {
    function f2bguard_get_interfaces() {
        if (function_exists('get_configured_interface_with_descr')) {
            $interfaces = get_configured_interface_with_descr();
            if (is_array($interfaces)) {
                return $interfaces;
            }
        }
        $interfaces = array();
        foreach (config_get_path('interfaces', array()) as $name => $data) {
            if ($name === 'lo0' || !is_array($data)) {
                continue;
            }
            $interfaces[$name] = (string)array_get_path($data, 'descr', strtoupper($name));
        }
        return $interfaces;
    }
}

if (!function_exists('f2bguard_get_cert')) {
    function f2bguard_get_cert($refid) {
        foreach (config_get_path('cert', array()) as $cert) {
            if (is_array($cert) && (string)array_get_path($cert, 'refid') === (string)$refid) {
                return $cert;
            }
        }
        return false;
    }
}

if (!function_exists('f2bguard_get_ca')) {
    function f2bguard_get_ca($refid) {
        foreach (config_get_path('ca', array()) as $ca) {
            if (is_array($ca) && (string)array_get_path($ca, 'refid') === (string)$refid) {
                return $ca;
            }
        }
        return false;
    }
}

if (!function_exists('f2bguard_certificate_choices')) {
    function f2bguard_certificate_choices($type) {
        $choices = array('' => gettext('Select a certificate'));
        $records = ($type === 'ca') ? config_get_path('ca', array()) : config_get_path('cert', array());
        foreach ($records as $record) {
            if (!is_array($record) || empty($record['refid'])) {
                continue;
            }
            $label = (string)array_get_path($record, 'descr', $record['refid']);
            if ($type !== 'ca' && empty($record['prv'])) {
                $label .= ' ' . gettext('(no private key)');
            }
            $choices[(string)$record['refid']] = $label;
        }
        return $choices;
    }
}

function f2bguard_limit_specs() {
    return array(
        'body_bytes' => array(1048576, 1024, 4194304, gettext('Maximum request bytes')),
        'events_per_request' => array(1000, 1, 10000, gettext('Maximum events per request')),
        'claims_per_client' => array(10000, 1, 100000, gettext('Maximum claims per endpoint')),
        'requests_per_minute' => array(120, 1, 100000, gettext('Requests per minute per endpoint')),
    );
}

if (!function_exists('f2bguard_validate_general')) {
    function f2bguard_validate_general($post, &$errors) {
        $listen = trim((string)array_get_path($post, 'listen', ''));
        if (@inet_pton($listen) === false || $listen === '0.0.0.0' || $listen === '::') {
            $errors[] = gettext('Listen address must be one explicit local IPv4 or IPv6 address; wildcard addresses are not allowed.');
        }
        $raw_port = array_get_path($post, 'port', '');
        if (!is_scalar($raw_port) || !preg_match('/^[0-9]{1,5}$/', (string)$raw_port)) {
            $errors[] = gettext('Port must be an integer.');
        }
        $port = intval($raw_port);
        if ($port < 1024 || $port > 65535) {
            $errors[] = gettext('Listen port must be between 1024 and 65535 because the backend runs as the unprivileged f2bguard user.');
        }
        foreach (f2bguard_limit_specs() as $key => $spec) {
            $raw = array_get_path($post, $key, $spec[0]);
            if (!is_scalar($raw) || !preg_match('/^[0-9]+$/', (string)$raw) || intval($raw) < $spec[1] || intval($raw) > $spec[2]) {
                $errors[] = sprintf(gettext('%s must be an integer between %d and %d.'), $spec[3], $spec[1], $spec[2]);
            }
        }
        $days = array_get_path($post, 'history_days', 90);
        if (!is_scalar($days) || !preg_match('/^[0-9]+$/', (string)$days) || intval($days) < 1 || intval($days) > 3650) {
            $errors[] = gettext('History retention must be between 1 and 3650 days.');
        }
        $enabled = !empty($post['enabled']);
        $cert = f2bguard_get_cert((string)array_get_path($post, 'tls_cert_ref', ''));
        $ca = f2bguard_get_ca((string)array_get_path($post, 'tls_ca_ref', ''));
        if ($enabled && (!$cert || empty($cert['crt']) || empty($cert['prv']))) {
            $errors[] = gettext('An enabled service requires a certificate with a private key from Certificate Manager.');
        }
        if ($enabled && (!$ca || empty($ca['crt']))) {
            $errors[] = gettext('An enabled service requires a trusted CA from Certificate Manager.');
        }
        $interfaces = array_values(array_filter((array)array_get_path($post, 'wan_interfaces', array()), function ($item) {
            return is_string($item) && preg_match('/^[A-Za-z0-9_.:-]+$/', $item);
        }));
        $available_interfaces = f2bguard_get_interfaces();
        foreach ($interfaces as $interface) {
            if (!array_key_exists($interface, $available_interfaces)) {
                $errors[] = sprintf(gettext('Selected interface %s is not configured on this firewall.'), f2bguard_html($interface));
            }
        }
        if ($enabled && empty($interfaces)) {
            $errors[] = gettext('Select at least one WAN interface before enabling enforcement.');
        }
        $alias = trim((string)array_get_path($post, 'whitelist_alias', ''));
        if ($alias !== '') {
            $alias_error = '';
            if (f2bguard_get_alias_addresses($alias, $alias_error) === false) {
                $errors[] = $alias_error;
            }
        }
        return empty($errors);
    }
}

if (!function_exists('f2bguard_validate_client')) {
    function f2bguard_validate_client($post, &$errors) {
        $id = trim((string)array_get_path($post, 'client_id', ''));
        f2bguard_validate_identifier($id, gettext('Client ID'), $errors);
        $fingerprints = preg_split('/[\s,]+/', trim((string)array_get_path($post, 'cert_sha256', '')), -1, PREG_SPLIT_NO_EMPTY);
        if (empty($fingerprints)) {
            $errors[] = gettext('Enter at least one SHA-256 client certificate fingerprint.');
        }
        foreach ($fingerprints as $fingerprint) {
            if (!preg_match('/^[a-fA-F0-9]{64}$/', $fingerprint)) {
                $errors[] = sprintf(gettext('Client fingerprint "%s" must be exactly 64 hexadecimal characters.'), f2bguard_html($fingerprint));
            }
        }
        $jails = preg_split('/[\s,]+/', trim((string)array_get_path($post, 'allowed_jails', '')), -1, PREG_SPLIT_NO_EMPTY);
        if (empty($jails)) {
            $errors[] = gettext('Each client must have at least one allowed jail.');
        }
        foreach ($jails as $jail) {
            f2bguard_validate_identifier($jail, gettext('Jail'), $errors);
        }
        return empty($errors);
    }
}

if (!function_exists('f2bguard_validate_runtime_clients')) {
    function f2bguard_validate_runtime_clients($clients, &$error) {
        $error = '';
        $normalized = array();
        foreach ((array)$clients as $client) {
            if (!is_array($client) || !preg_match('/^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$/', (string)array_get_path($client, 'id', ''))) {
                $error = gettext('A configured client has an invalid identifier.');
                return false;
            }
            $fingerprints = array_values(array_filter((array)array_get_path($client, 'cert_sha256', array()), function ($item) {
                return is_string($item) && preg_match('/^[a-fA-F0-9]{64}$/', $item);
            }));
            $jails = array_values(array_filter((array)array_get_path($client, 'allowed_jails', array()), function ($item) {
                return is_string($item) && preg_match('/^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$/', $item);
            }));
            if (empty($fingerprints) || empty($jails)) {
                $error = gettext('Every configured client needs valid certificate fingerprints and at least one allowed jail.');
                return false;
            }
            $normalized[] = array(
                'id' => (string)$client['id'],
                'cert_sha256' => array_values(array_unique(array_map('strtolower', $fingerprints))),
                'allowed_jails' => array_values(array_unique($jails)),
            );
        }
        return $normalized;
    }
}

if (!function_exists('f2bguard_store_config')) {
    function f2bguard_config_for_storage($cfg) {
        $persist = is_array($cfg) ? $cfg : array();
        $persist['enabled'] = f2bguard_normalize_enabled(array_get_path($persist, 'enabled', false)) ? 'yes' : 'no';
        foreach (array('clients', 'jails', 'wan_interfaces') as $key) {
            $value = array_values((array)array_get_path($persist, $key, array()));
            $encoded = json_encode($value, JSON_UNESCAPED_SLASHES);
            if ($encoded === false || json_last_error() !== JSON_ERROR_NONE) {
                return false;
            }
            $persist[$key . '_json'] = $encoded;
            unset($persist[$key]);
        }
        return $persist;
    }

    function f2bguard_store_config($cfg, $description) {
        $previous = config_get_path('installedpackages/f2bguard/config/0', array());
        $persist = f2bguard_config_for_storage($cfg);
        if ($persist === false) {
            return false;
        }
        config_set_path('installedpackages/f2bguard/config/0', $persist);
        $result = write_config($description);
        if ($result === false || $result === -1) {
            config_set_path('installedpackages/f2bguard/config/0', $previous);
            return false;
        }
        return true;
    }
}

if (!function_exists('f2bguard_render_tabs')) {
    function f2bguard_render_tabs($active) {
        $tabs = array(
            'general' => array(gettext('General'), '/f2bguard.php'),
            'clients' => array(gettext('Clients'), '/f2bguard_clients.php'),
            'jails' => array(gettext('Jails'), '/f2bguard_jails.php'),
            'status' => array(gettext('Status'), '/f2bguard_status.php'),
        );
        echo '<ul class="nav nav-tabs" role="tablist">';
        foreach ($tabs as $key => $tab) {
            $class = ($key === $active) ? ' class="active"' : '';
            printf('<li role="presentation"%s><a href="%s">%s</a></li>', $class, f2bguard_html($tab[1]), f2bguard_html($tab[0]));
        }
        echo '</ul><br />';
    }
}

if (!function_exists('f2bguard_atomic_write')) {
    function f2bguard_atomic_write($path, $contents, $mode = 0640, $group = 'f2bguard') {
        $directory = dirname($path);
        if (!is_dir($directory)) {
            if (!mkdir($directory, 0750, true) || !@chmod($directory, 0750) || !@chown($directory, 'root') || !@chgrp($directory, $group)) {
                return false;
            }
        }
        /* Never follow a service-writable or symlinked trust directory. */
        for ($parent = $directory; ; $parent = dirname($parent)) {
            $info = @lstat($parent);
            if ($info === false || ($info['mode'] & 0170000) !== 0040000 || $info['uid'] !== 0 || ($info['mode'] & 0022) !== 0) {
                return false;
            }
            if ($parent === '/') { break; }
        }
        $tmp = $path . '.new.' . bin2hex(random_bytes(8));
        $oldmask = umask(0077);
        $stream = @fopen($tmp, 'x');
        umask($oldmask);
        if ($stream === false) { return false; }
        $written = fwrite($stream, $contents);
        $flushed = fflush($stream);
        if (function_exists('fsync')) { $flushed = fsync($stream) && $flushed; }
        fclose($stream);
        if ($written !== strlen($contents) || !$flushed) {
            @unlink($tmp);
            return false;
        }
        if (!@chmod($tmp, $mode) || !@chown($tmp, 'root') || !@chgrp($tmp, $group)) {
            @unlink($tmp);
            return false;
        }
        if (!rename($tmp, $path)) {
            @unlink($tmp);
            return false;
        }
        return @chmod($path, $mode) && @chown($path, 'root') && @chgrp($path, $group);
    }
}

if (!function_exists('f2bguard_runtime_config')) {
    function f2bguard_runtime_config($cfg) {
        $runtime = f2bguard_default_config();
        $runtime['enabled'] = f2bguard_normalize_enabled(array_get_path($cfg, 'enabled', false));
        $runtime['listen'] = (string)$cfg['listen'];
        $runtime['port'] = intval($cfg['port']);
        foreach (f2bguard_limit_specs() as $key => $spec) {
            $runtime['limits'][$key] = intval(array_get_path($cfg, 'limits/' . $key, $spec[0]));
        }
        $runtime['history_days'] = intval(array_get_path($cfg, 'history_days', 90));
        $client_error = '';
        $clients = f2bguard_validate_runtime_clients(array_get_path($cfg, 'clients', array()), $client_error);
        $runtime['clients'] = ($clients === false) ? array() : $clients;
        $runtime['tls'] = array(
            'cert' => '/usr/local/etc/f2bguard/tls/server.crt',
            'key' => '/usr/local/etc/f2bguard/tls/server.key',
            'ca' => '/usr/local/etc/f2bguard/tls/ca.crt',
        );
        return $runtime;
    }
}

if (!function_exists('f2bguard_resync_config')) {
    function f2bguard_apply_service_state($enabled, $reload_filter = true) {
        if (!function_exists('mwexec')) {
            return true;
        }
        $flag = $enabled ? 'YES' : 'NO';
        if (!f2bguard_atomic_write('/usr/local/etc/rc.conf.d/f2bguard', "f2bguard_enable=\"" . $flag . "\"\n", 0644, 'wheel')) {
            $GLOBALS['f2bguard_last_error'] = gettext('Unable to write the pfSense service enable state.');
            return false;
        }
        $command = $enabled ? '/usr/sbin/service f2bguard restart' : '/usr/sbin/service f2bguard stop';
        $service_rc = mwexec($command, true);
        if ($service_rc === false || intval($service_rc) !== 0) {
            $GLOBALS['f2bguard_last_error'] = sprintf(gettext('The f2bguard service command failed with status %s.'), f2bguard_html((string)$service_rc));
            f2bguard_atomic_write('/usr/local/etc/rc.conf.d/f2bguard', "f2bguard_enable=\"NO\"\n", 0644, 'wheel');
            mwexec('/usr/sbin/service f2bguard stop', true);
            return false;
        }
        if ($reload_filter) {
            $filter_rc = mwexec('/etc/rc.filter_configure_sync', true);
            if ($filter_rc === false || intval($filter_rc) !== 0) {
                $GLOBALS['f2bguard_last_error'] = sprintf(gettext('The pfSense filter reload failed with status %s.'), f2bguard_html((string)$filter_rc));
                f2bguard_atomic_write('/usr/local/etc/rc.conf.d/f2bguard', "f2bguard_enable=\"NO\"\n", 0644, 'wheel');
                mwexec('/usr/sbin/service f2bguard stop', true);
                return false;
            }
        }
        return true;
    }

    function f2bguard_disable_runtime($cfg, $error, $apply_service = true, $reload_filter = true) {
        $GLOBALS['f2bguard_last_error'] = $error;
        $runtime = f2bguard_runtime_config($cfg);
        $runtime['enabled'] = false;
        $runtime_json = json_encode($runtime, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
        if ($runtime_json === false || !f2bguard_atomic_write('/usr/local/etc/f2bguard/config.json', $runtime_json . PHP_EOL, 0640)) {
            $GLOBALS['f2bguard_last_error'] .= ' ' . gettext('The disabled runtime configuration could not be written.');
        }
        if ($apply_service && !f2bguard_apply_service_state(false, $reload_filter)) {
            return false;
        }
        return false;
    }

    function f2bguard_certificate_material_available($cfg, $cert, $ca) {
        if (!f2bguard_normalize_enabled(array_get_path($cfg, 'enabled', false))) {
            return true;
        }
        return is_array($cert) && (string)array_get_path($cert, 'crt', '') !== ''
            && (string)array_get_path($cert, 'prv', '') !== ''
            && is_array($ca) && (string)array_get_path($ca, 'crt', '') !== '';
    }

    function f2bguard_resync_config($apply_service = true) {
        $cfg = f2bguard_get_config();
        if (!empty($cfg['_config_error'])) {
            return f2bguard_disable_runtime($cfg, $cfg['_config_error'], $apply_service);
        }
        $error = '';
        $clients = f2bguard_validate_runtime_clients(array_get_path($cfg, 'clients', array()), $error);
        if ($clients === false) {
            return f2bguard_disable_runtime($cfg, $error, $apply_service);
        }
        $whitelist = f2bguard_get_alias_addresses((string)array_get_path($cfg, 'whitelist_alias', ''), $error);
        $whitelist_path = '/usr/local/etc/f2bguard/whitelist.txt';
        if ($whitelist === false) {
            /* Keep the last valid snapshot, but disable the runtime and stop
             * the backend so it cannot accept new updates against stale policy. */
            return f2bguard_disable_runtime($cfg, $error, $apply_service);
        } else {
            if (!f2bguard_atomic_write($whitelist_path, implode(PHP_EOL, $whitelist) . (count($whitelist) ? PHP_EOL : ''), 0640)) {
                return f2bguard_disable_runtime($cfg, gettext('Unable to write the root-owned whitelist snapshot.'), $apply_service);
            }
        }

        $cert = f2bguard_get_cert((string)array_get_path($cfg, 'tls_cert_ref', ''));
        $ca = f2bguard_get_ca((string)array_get_path($cfg, 'tls_ca_ref', ''));
        if (!f2bguard_certificate_material_available($cfg, $cert, $ca)) {
            return f2bguard_disable_runtime($cfg, gettext('The enabled service references a missing Certificate Manager certificate, private key, or CA.'), $apply_service);
        }
        $tlsdir = '/usr/local/etc/f2bguard/tls';
        foreach (array(
            array($cert, 'crt', $tlsdir . '/server.crt'),
            array($cert, 'prv', $tlsdir . '/server.key'),
            array($ca, 'crt', $tlsdir . '/ca.crt'),
        ) as $pem) {
            if (!$pem[0] || (string)array_get_path($pem[0], $pem[1]) === '') {
                continue;
            }
            $decoded = base64_decode((string)$pem[0][$pem[1]], true);
            if ($decoded === false || !f2bguard_atomic_write($pem[2], $decoded, 0640)) {
                return f2bguard_disable_runtime($cfg, gettext('Unable to write a Certificate Manager PEM with root ownership and service-readable permissions.'), $apply_service);
            }
        }

        $runtime = f2bguard_runtime_config($cfg);
        if (!f2bguard_atomic_write('/usr/local/etc/f2bguard/config.json', json_encode($runtime, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . PHP_EOL, 0640)) {
            $GLOBALS['f2bguard_last_error'] = gettext('Unable to write the root-owned runtime configuration.');
            return false;
        }
        if ($apply_service && !f2bguard_apply_service_state(!empty($runtime['enabled']))) {
            $runtime['enabled'] = false;
            $disabled_json = json_encode($runtime, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
            if ($disabled_json !== false) {
                f2bguard_atomic_write('/usr/local/etc/f2bguard/config.json', $disabled_json . PHP_EOL, 0640);
            }
            return false;
        }
        return $whitelist !== false;
    }
}

if (!function_exists('f2bguard_install')) {
    function f2bguard_install() {
        $ok = true;
        if (function_exists('mwexec')) {
            if (mwexec('/usr/sbin/pw group show f2bguard', true) !== 0) {
                $ok = (mwexec('/usr/sbin/pw groupadd f2bguard', true) === 0) && $ok;
            }
            if (mwexec('/usr/sbin/pw user show f2bguard', true) !== 0) {
                $ok = (mwexec('/usr/sbin/pw useradd f2bguard -g f2bguard -s /usr/sbin/nologin -d /nonexistent', true) === 0) && $ok;
            }
        }
        foreach (array('/usr/local/etc/f2bguard', '/usr/local/etc/f2bguard/tls', '/var/db/f2bguard', '/var/run/f2bguard') as $directory) {
            if (!is_dir($directory) && !@mkdir($directory, 0750, true)) {
                $ok = false;
            }
        }
        if (!@chown('/usr/local/etc/f2bguard', 'root') || !@chgrp('/usr/local/etc/f2bguard', 'f2bguard') || !@chmod('/usr/local/etc/f2bguard', 0750) ||
            !@chown('/usr/local/etc/f2bguard/tls', 'root') || !@chgrp('/usr/local/etc/f2bguard/tls', 'f2bguard') || !@chmod('/usr/local/etc/f2bguard/tls', 0750) ||
            !@chown('/var/db/f2bguard', 'f2bguard') || !@chgrp('/var/db/f2bguard', 'f2bguard') || !@chmod('/var/db/f2bguard', 0750) ||
            !@chown('/var/run/f2bguard', 'root') || !@chgrp('/var/run/f2bguard', 'f2bguard') || !@chmod('/var/run/f2bguard', 0750)) {
            $ok = false;
        }
        if (!$ok || !f2bguard_resync_config(false)) {
            return false;
        }
        return true;
    }
}

if (!function_exists('f2bguard_pre_deinstall')) {
    function f2bguard_pre_deinstall() {
        if (function_exists('mwexec')) {
            return mwexec('/usr/sbin/service f2bguard stop', true) === 0;
        }
        return true;
    }
}

if (!function_exists('f2bguard_deinstall')) {
    function f2bguard_deinstall() {
        @unlink('/usr/local/etc/rc.conf.d/f2bguard');
        foreach (array(
            '/usr/local/etc/f2bguard/config.json',
            '/usr/local/etc/f2bguard/whitelist.txt',
            '/usr/local/etc/f2bguard/tls/server.crt',
            '/usr/local/etc/f2bguard/tls/server.key',
            '/usr/local/etc/f2bguard/tls/ca.crt',
        ) as $path) {
            @unlink($path);
        }
        /* Keep /var/db/f2bguard so reinstall does not discard durable claims. */
    }
}

if (!function_exists('f2bguard_refresh_whitelist')) {
    /* Called on every filter generation, including changes to Firewall > Aliases.
     * This must not request another filter reload (which would recurse). */
    function f2bguard_refresh_whitelist($cfg) {
        $error = '';
        $entries = f2bguard_get_alias_addresses((string)array_get_path($cfg, 'whitelist_alias', ''), $error);
        if ($entries !== false && f2bguard_atomic_write('/usr/local/etc/f2bguard/whitelist.txt', implode("\n", $entries) . "\n", 0640)) {
            return true;
        }
        /* Do not invoke filter_configure_sync from its own callback. The
         * current filter remains authoritative while the backend is stopped. */
        return f2bguard_disable_runtime($cfg, $error ?: gettext('Unable to refresh the trusted whitelist.'), true, false);
    }
}

if (!function_exists('f2bguard_generate_rules')) {
    /* Called by pfSense during filter_configure_sync(). */
    function f2bguard_generate_rules($ruletype = 'pfearly') {
        global $reserved_table_names;
        $cfg = f2bguard_get_config();
        if (!$cfg['enabled'] || $ruletype !== 'pfearly') {
            return '';
        }
        $interfaces = (array)array_get_path($cfg, 'wan_interfaces', array());
        if (empty($interfaces)) {
            return '';
        }
        /* reload_filter() removes tables absent from aliases and this registry.
         * Register during rule generation so the subsequent cleanup retains
         * our fixed tables without changing pfSense core files. */
        foreach (array('f2bguard_v4', 'f2bguard_v6') as $table) {
            $reserved_table_names[$table] = array('name' => $table, 'type' => 'host',
                'descr' => 'Fail2Ban Guard managed block table', 'address' => '', 'detail' => '');
        }
        f2bguard_refresh_whitelist($cfg);
        $rules = "# Fail2Ban Guard package-owned tables and rules\n";
        $rules .= "table <f2bguard_v4> persist\n";
        $rules .= "table <f2bguard_v6> persist\n";
        foreach ($interfaces as $interface) {
            if (!is_string($interface) || !preg_match('/^[A-Za-z0-9_.:-]+$/', $interface)) {
                continue;
            }
            if (!array_key_exists($interface, f2bguard_get_interfaces())) {
                continue;
            }
            $real = function_exists('get_real_interface') ? get_real_interface($interface) : $interface;
            if (!is_string($real) || !preg_match('/^[A-Za-z0-9_.:-]+$/', $real)) {
                continue;
            }
            $rules .= sprintf("block in quick on %s inet from <f2bguard_v4> to any label \"f2bguard\"\n", $real);
            $rules .= sprintf("block in quick on %s inet6 from <f2bguard_v6> to any label \"f2bguard\"\n", $real);
        }
        return $rules;
    }
}

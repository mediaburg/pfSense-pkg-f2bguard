<?php
/* Offline tests of pure package functions; no pfSense files or rules modified. */
if (!function_exists('gettext')) { function gettext($s) { return $s; } }
$GLOBALS['fixture'] = array();
function array_get_path($array, $path, $default = null) {
    foreach (explode('/', $path) as $part) {
        if (!is_array($array) || !array_key_exists($part, $array)) { return $default; }
        $array = $array[$part];
    }
    return $array;
}
function config_get_path($path, $default = null) { return array_get_path($GLOBALS['fixture'], $path, $default); }
function get_configured_interface_with_descr() { return array('wan' => 'WAN', 'opt1' => 'WAN2'); }
function get_real_interface($name) { return array('wan' => 'vtnet0', 'opt1' => 'vtnet2')[$name] ?? false; }
function check($condition, $description) { if (!$condition) { throw new Exception($description); } }
function f2bguard_refresh_whitelist($cfg) { return true; }
require __DIR__ . '/../pfsense/files/usr/local/pkg/f2bguard.inc';
check(f2bguard_default_config()['enabled'] === false, 'must default disabled');
check(f2bguard_normalize_ip_or_cidr('2001:DB8::1') === '2001:db8::1/128', 'canonical IPv6');
check(f2bguard_normalize_ip_or_cidr('0.0.0.0/0') === '0.0.0.0/0', 'explicit broad whitelist supported');
check(f2bguard_normalize_ip_or_cidr('203.0.113.1; reboot') === false, 'no commands in whitelist');
check(f2bguard_normalize_ip_or_cidr('203.0.113.1/33') === false, 'invalid prefix rejected');
$GLOBALS['fixture']['aliases']['alias'] = array(array('name'=>'safe','type'=>'network','address'=>'203.0.113.0/24 2001:db8::/32'));
$error=''; $addresses=f2bguard_get_alias_addresses('safe',$error);
check(count($addresses) === 2 && $error === '', 'literal whitelist resolution');
check(f2bguard_get_alias_addresses('missing',$error) === false, 'missing alias not empty allowlist');
$GLOBALS['fixture']['aliases']['alias'][0]['address']='example.com';
check(f2bguard_get_alias_addresses('safe',$error) === false, 'DNS entry rejected');
$GLOBALS['fixture']['aliases']['alias'][0]['type']='urltable';
check(f2bguard_get_alias_addresses('safe',$error) === false, 'dynamic alias rejected');
$cfg=f2bguard_default_config();$cfg['wan_interfaces']=array('wan');$cfg['jails']=array('recidive');
$runtime=f2bguard_runtime_config($cfg);
check(!isset($runtime['wan_interfaces']) && !isset($runtime['jails']), 'pfSense-only fields not exported to strict receiver');
check($runtime['whitelist_file'] === '/usr/local/etc/f2bguard/whitelist.txt', 'root-controlled whitelist path');
$cfg['clients']=array(array('id'=>'collector','cert_sha256'=>array(str_repeat('a', 64)),'allowed_jails'=>array('recidive')));
$stored=f2bguard_config_for_storage($cfg);
check(is_array($stored) && !isset($stored['clients']) && !isset($stored['jails']) && !isset($stored['wan_interfaces']), 'list fields stored as scalar JSON');
check(is_string($stored['clients_json']) && is_string($stored['jails_json']) && is_string($stored['wan_interfaces_json']), 'scalar JSON fields are present');
$GLOBALS['fixture']['installedpackages']['f2bguard']['config'][0]=$stored;
$roundtrip=f2bguard_get_config();
check($roundtrip['clients'][0]['allowed_jails'][0] === 'recidive', 'nested client permissions survive config round trip');
check($roundtrip['jails'] === array('recidive') && $roundtrip['wan_interfaces'] === array('wan'), 'jails and interfaces survive config round trip');
$GLOBALS['fixture']['installedpackages']['f2bguard']['config'][0]['clients_json']='not-json';
$malformed=f2bguard_get_config();
check(!empty($malformed['_config_error']) && $malformed['clients'] === array(), 'malformed scalar JSON cannot resurrect legacy clients');
check(f2bguard_certificate_material_available(array('enabled'=>false), false, false), 'disabled service tolerates missing certificate references');
check(!f2bguard_certificate_material_available(array('enabled'=>true), false, false), 'enabled service rejects missing certificate references');
check(f2bguard_certificate_material_available(array('enabled'=>true), array('crt'=>'Y3J0','prv'=>'a2V5'), array('crt'=>'Y2E=')), 'enabled service accepts complete certificate references');
$GLOBALS['fixture']['installedpackages']['f2bguard']['config'][0]=array('enabled'=>'');
$empty_tag=f2bguard_get_config();
check($empty_tag['enabled'] === false, 'empty XML enabled tag fails closed');
$enabled_storage=f2bguard_config_for_storage(array('enabled'=>true));
check($enabled_storage['enabled'] === 'yes', 'enabled state uses explicit XML-safe scalar');
$GLOBALS['fixture']['installedpackages']['f2bguard']['config'][0]=$enabled_storage;
check(f2bguard_get_config()['enabled'] === true, 'explicit enabled state survives config round trip');
$disabled_storage=f2bguard_config_for_storage(array('enabled'=>false));
check($disabled_storage['enabled'] === 'no', 'disabled state uses explicit XML-safe scalar');
$GLOBALS['fixture']['installedpackages']['f2bguard']['config'][0]=$disabled_storage;
check(f2bguard_get_config()['enabled'] === false, 'explicit disabled state survives config round trip');
$GLOBALS['fixture']['installedpackages']['f2bguard']['config']=$cfg;
$GLOBALS['reserved_table_names']=array();
check(f2bguard_generate_rules('pfearly') === '', 'disabled package emits no PF rules');
check($GLOBALS['reserved_table_names'] === array(), 'disabled package does not retain tables during cleanup');
$cfg['enabled']=true;$GLOBALS['fixture']['installedpackages']['f2bguard']['config']=$cfg;
$rules=f2bguard_generate_rules('pfearly');
check(isset($GLOBALS['reserved_table_names']['f2bguard_v4'], $GLOBALS['reserved_table_names']['f2bguard_v6']), 'enabled tables survive pfSense reserved-table cleanup');
check(strpos($rules, 'block in quick on vtnet0 inet from <f2bguard_v4> to any') !== false, 'IPv4 source block any destination');
check(strpos($rules, 'block in quick on vtnet0 inet6 from <f2bguard_v6> to any') !== false, 'IPv6 source block any destination');
check(strpos($rules, 'pass ') === false, 'whitelist must not create firewall bypass');
echo "pfSense pure-function checks passed (no runtime integration tested).\n";

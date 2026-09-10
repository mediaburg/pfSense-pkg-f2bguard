<?php
require_once('guiconfig.inc');
require_once('/usr/local/pkg/f2bguard.inc');

$cfg = f2bguard_get_config();
$runtime_path = '/usr/local/etc/f2bguard/config.json';
$whitelist_path = '/usr/local/etc/f2bguard/whitelist.txt';
$runtime_present = is_file($runtime_path) && !is_link($runtime_path);
$runtime_enabled = false;
$runtime_valid = false;
if ($runtime_present) {
    $runtime_data = @json_decode((string)@file_get_contents($runtime_path), true);
    if (is_array($runtime_data) && isset($runtime_data['enabled']) && is_bool($runtime_data['enabled'])) {
        $runtime_valid = true;
        $runtime_enabled = $runtime_data['enabled'];
    }
}
$whitelist_present = is_file($whitelist_path) && !is_link($whitelist_path);
$whitelist_valid = $whitelist_present;
$whitelist_count = 0;
if ($whitelist_present) {
    $lines = @file($whitelist_path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    if ($lines === false) {
        $whitelist_valid = false;
    } else {
        foreach ($lines as $line) {
            if (f2bguard_normalize_ip_or_cidr(trim($line)) === false) {
                $whitelist_valid = false;
                break;
            }
            $whitelist_count++;
        }
    }
}
$backend_pid = @file_get_contents('/var/run/f2bguard/server.pid');
$helper_pid = @file_get_contents('/var/run/f2bguard/helper.pid');
$service_running = null;
if (function_exists('mwexec')) {
    $service_rc = mwexec('/usr/sbin/service f2bguard status', true);
    $service_running = ($service_rc !== false && intval($service_rc) === 0);
}
$pgtitle = array(gettext('Services'), gettext('Fail2Ban Guard'), gettext('Status'));
$pglinks = array('', '/f2bguard.php', '@self');
include('head.inc');
f2bguard_render_tabs('status');
?>
<div class="panel panel-default"><div class="panel-heading"><h2 class="panel-title"><?=gettext('Fail2Ban Guard status')?></h2></div><div class="panel-body">
<table class="table table-striped"><tbody>
<tr><th><?=gettext('Configured')?></th><td><?=!empty($cfg['enabled']) ? '<span class="label label-warning">' . f2bguard_html(gettext('Enabled')) . '</span>' : '<span class="label label-default">' . f2bguard_html(gettext('Disabled')) . '</span>'?></td></tr>
<tr><th><?=gettext('Runtime configuration')?></th><td><?= $runtime_valid ? '<span class="label label-success">' . f2bguard_html($runtime_enabled ? gettext('Enabled') : gettext('Disabled')) . '</span>' : '<span class="label label-danger">' . f2bguard_html($runtime_present ? gettext('Invalid') : gettext('Missing')) . '</span>' ?></td></tr>
<tr><th><?=gettext('Service state')?></th><td><?php if ($service_running === null): ?><span class="label label-default"><?=f2bguard_html(gettext('Unavailable'))?></span><?php elseif ($service_running): ?><span class="label label-success"><?=f2bguard_html(gettext('Running'))?></span><?php else: ?><span class="label label-warning"><?=f2bguard_html(gettext('Stopped or unhealthy'))?></span><?php endif; ?></td></tr>
<tr><th><?=gettext('Whitelist snapshot')?></th><td><?= $whitelist_valid ? f2bguard_html(sprintf(gettext('Valid (%d entries)'), $whitelist_count)) : '<span class="text-danger">' . f2bguard_html(gettext('Missing or invalid; new enforcement updates are blocked')) . '</span>' ?></td></tr>
<tr><th><?=gettext('Backend PID file')?></th><td><code><?=f2bguard_html(trim((string)$backend_pid) ?: gettext('not present'))?></code></td></tr>
<tr><th><?=gettext('PF helper PID file')?></th><td><code><?=f2bguard_html(trim((string)$helper_pid) ?: gettext('not present'))?></code></td></tr>
</tbody></table>
<?php if (!empty($cfg['enabled']) && (!$runtime_valid || !$runtime_enabled)): ?><div class="alert alert-danger"><?=gettext('The service is enabled in pfSense but the runtime is disabled or invalid. Enforcement is not healthy.')?></div><?php endif; ?>
<?php if (!empty($cfg['enabled']) && !$whitelist_valid): ?><div class="alert alert-warning"><?=gettext('The whitelist snapshot is not valid. The last applied PF tables are preserved and new updates must fail closed until the alias resolves to literal IP/CIDR entries.')?></div><?php endif; ?>
</div></div>
<div class="panel panel-warning"><div class="panel-heading"><h2 class="panel-title"><?=gettext('High availability')?></h2></div><div class="panel-body"><p><?=gettext('Runtime claim replication and automatic failover are not implemented. CARP/pfsync and pfSense XMLRPC may carry static package configuration only; they do not synchronize the service database or active claims. HA production use is therefore unsupported and degraded until an explicit runtime replication design is added.')?></p></div></div>
<?php include('foot.inc'); ?>

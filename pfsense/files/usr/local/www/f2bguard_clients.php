<?php
require_once('guiconfig.inc');
require_once('/usr/local/pkg/f2bguard.inc');

$cfg = f2bguard_get_config();
$clients = is_array($cfg['clients']) ? array_values($cfg['clients']) : array();
$input_errors = array();
$savemsg = '';
$edit = (isset($_GET['id']) && ctype_digit((string)$_GET['id'])) ? intval($_GET['id']) : -1;
$form = array('client_id' => '', 'cert_sha256' => '', 'allowed_jails' => '');
if ($edit >= 0 && isset($clients[$edit])) {
    $form['client_id'] = (string)array_get_path($clients[$edit], 'id', '');
    $form['cert_sha256'] = implode("\n", (array)array_get_path($clients[$edit], 'cert_sha256', array()));
    $form['allowed_jails'] = implode("\n", (array)array_get_path($clients[$edit], 'allowed_jails', array()));
}
if ($_POST) {
    $action = (string)($_POST['action'] ?? '');
    $index = (isset($_POST['index']) && ctype_digit((string)$_POST['index'])) ? intval($_POST['index']) : -1;
    if ($action === 'delete' && $index >= 0 && isset($clients[$index])) {
        array_splice($clients, $index, 1);
        $cfg['clients'] = $clients;
        if (f2bguard_store_config($cfg, gettext('Removed a Fail2Ban Guard client.'))) {
            if (f2bguard_resync_config(true)) {
                $savemsg = gettext('Client removed.');
            } else {
                $input_errors[] = $GLOBALS['f2bguard_last_error'] ?? gettext('Runtime configuration could not be applied.');
            }
        } else {
            $input_errors[] = gettext('Unable to save the pfSense configuration.');
        }
    } elseif ($action === 'save') {
        f2bguard_validate_client($_POST, $input_errors);
        $id = trim((string)($_POST['client_id'] ?? ''));
        foreach ($clients as $client_index => $client) {
            if ($client_index !== $index && strcasecmp((string)array_get_path($client, 'id', ''), $id) === 0) {
                $input_errors[] = gettext('Client ID is already in use.');
            }
        }
        if (empty($input_errors)) {
            $fingerprints = preg_split('/[\s,]+/', trim((string)$_POST['cert_sha256']), -1, PREG_SPLIT_NO_EMPTY);
            $jails = preg_split('/[\s,]+/', trim((string)($_POST['allowed_jails'] ?? '')), -1, PREG_SPLIT_NO_EMPTY);
            $record = array(
                'id' => $id,
                'cert_sha256' => array_values(array_unique(array_map('strtolower', $fingerprints))),
                'allowed_jails' => array_values(array_unique($jails)),
            );
            if ($index >= 0 && isset($clients[$index])) {
                $clients[$index] = $record;
            } else {
                $clients[] = $record;
            }
            $cfg['clients'] = $clients;
            if (f2bguard_store_config($cfg, gettext('Saved a Fail2Ban Guard client.'))) {
                if (f2bguard_resync_config(true)) {
                    $savemsg = gettext('Client saved.');
                    $edit = -1;
                    $form = array('client_id' => '', 'cert_sha256' => '', 'allowed_jails' => '');
                } else {
                    $input_errors[] = $GLOBALS['f2bguard_last_error'] ?? gettext('Runtime configuration could not be applied.');
                }
            } else {
                $input_errors[] = gettext('Unable to save the pfSense configuration.');
            }
        } else {
            $form = array('client_id' => $id, 'cert_sha256' => (string)$_POST['cert_sha256'], 'allowed_jails' => (string)($_POST['allowed_jails'] ?? ''));
        }
    }
}
$cfg = f2bguard_get_config();
$clients = is_array($cfg['clients']) ? array_values($cfg['clients']) : array();
$pgtitle = array(gettext('Services'), gettext('Fail2Ban Guard'), gettext('Clients'));
$pglinks = array('', '/f2bguard.php', '@self');
include('head.inc');
f2bguard_render_tabs('clients');
if ($input_errors) {
    print_input_errors($input_errors);
}
if ($savemsg) {
    print_info_box($savemsg, 'success');
}
?>
<div class="panel panel-default">
  <div class="panel-heading"><h2 class="panel-title"><?=($edit >= 0 ? gettext('Edit client') : gettext('Add client'))?></h2></div>
  <div class="panel-body">
    <form method="post" action="f2bguard_clients.php<?=($edit >= 0 ? '?id=' . intval($edit) : '')?>" autocomplete="off">
      <input type="hidden" name="action" value="save" />
      <input type="hidden" name="index" value="<?=intval($edit)?>" />
      <div class="form-group"><label for="client_id"><?=gettext('Client ID')?></label><input id="client_id" name="client_id" class="form-control" value="<?=f2bguard_html($form['client_id'])?>" required="required" /><p class="help-block"><?=gettext('Stable identifier used for per-client sequence state.')?></p></div>
      <div class="form-group"><label for="cert_sha256"><?=gettext('Allowed client certificate SHA-256 fingerprints')?></label><textarea id="cert_sha256" name="cert_sha256" class="form-control" rows="3" required="required"><?=f2bguard_html($form['cert_sha256'])?></textarea><p class="help-block"><?=gettext('One 64-character hexadecimal DER certificate fingerprint per line. Unknown fingerprints are denied.')?></p></div>
      <div class="form-group"><label for="allowed_jails"><?=gettext('Allowed jails')?></label><textarea id="allowed_jails" name="allowed_jails" class="form-control" rows="3"><?=f2bguard_html($form['allowed_jails'])?></textarea><p class="help-block"><?=gettext('One jail identifier per line. A client cannot submit events for other jails.')?></p></div>
      <button type="submit" class="btn btn-primary"><?=gettext('Save client')?></button>
      <?php if ($edit >= 0): ?><a class="btn btn-default" href="f2bguard_clients.php"><?=gettext('Cancel')?></a><?php endif; ?>
    </form>
  </div>
</div>
<div class="panel panel-default"><div class="panel-heading"><h2 class="panel-title"><?=gettext('Configured clients')?></h2></div><div class="panel-body table-responsive">
<table class="table table-striped table-hover"><thead><tr><th><?=gettext('ID')?></th><th><?=gettext('Fingerprints')?></th><th><?=gettext('Jails')?></th><th><?=gettext('Actions')?></th></tr></thead><tbody>
<?php foreach ($clients as $index => $client): ?>
<tr><td><?=f2bguard_html(array_get_path($client, 'id', ''))?></td><td><code><?=f2bguard_html(implode(', ', (array)array_get_path($client, 'cert_sha256', array())))?></code></td><td><?=f2bguard_html(implode(', ', (array)array_get_path($client, 'allowed_jails', array())))?></td><td><a class="btn btn-xs btn-default" href="f2bguard_clients.php?id=<?=intval($index)?>"><?=gettext('Edit')?></a> <form method="post" action="f2bguard_clients.php" style="display:inline"><input type="hidden" name="action" value="delete" /><input type="hidden" name="index" value="<?=intval($index)?>" /><button type="submit" class="btn btn-xs btn-danger" onclick="return confirm('<?=f2bguard_html(gettext('Remove this client?'))?>');"><?=gettext('Delete')?></button></form></td></tr>
<?php endforeach; ?>
<?php if (!$clients): ?><tr><td colspan="4"><?=gettext('No clients configured.')?></td></tr><?php endif; ?>
</tbody></table></div></div>
<?php include('foot.inc'); ?>

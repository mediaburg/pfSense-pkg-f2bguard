<?php
require_once('guiconfig.inc');
require_once('/usr/local/pkg/f2bguard.inc');

$cfg = f2bguard_get_config();
$input_errors = array();
$savemsg = '';
if ($_POST) {
    if (($_POST['action'] ?? '') === 'save') {
        f2bguard_validate_general($_POST, $input_errors);
        if (empty($input_errors)) {
            $cfg['enabled'] = !empty($_POST['enabled']);
            $cfg['listen'] = trim((string)$_POST['listen']);
            $cfg['port'] = intval($_POST['port']);
            foreach (f2bguard_limit_specs() as $key => $spec) {
                $cfg['limits'][$key] = intval($_POST[$key] ?? $spec[0]);
            }
            $cfg['history_days'] = intval($_POST['history_days'] ?? 90);
            $cfg['tls_cert_ref'] = trim((string)($_POST['tls_cert_ref'] ?? ''));
            $cfg['tls_ca_ref'] = trim((string)($_POST['tls_ca_ref'] ?? ''));
            $cfg['whitelist_alias'] = trim((string)($_POST['whitelist_alias'] ?? ''));
            $cfg['wan_interfaces'] = array_values(array_filter((array)($_POST['wan_interfaces'] ?? ''), function ($value) {
                return is_string($value) && preg_match('/^[A-Za-z0-9_.:-]+$/', $value);
            }));
            if (f2bguard_store_config($cfg, gettext('Saved Fail2Ban Guard settings.'))) {
                if (f2bguard_resync_config(true)) {
                    $savemsg = gettext('Settings saved and service state updated.');
                } else {
                    $input_errors[] = $GLOBALS['f2bguard_last_error'] ?? gettext('Runtime configuration could not be applied.');
                }
            } else {
                $input_errors[] = gettext('Unable to save the pfSense configuration.');
            }
        }
    }
}
$cfg = f2bguard_get_config();
$selected_interfaces = (array)array_get_path($cfg, 'wan_interfaces', array());
$pgtitle = array(gettext('Services'), gettext('Fail2Ban Guard'));
$pglinks = array('', '@self');
include('head.inc');
f2bguard_render_tabs('general');
if ($input_errors) {
    print_input_errors($input_errors);
}
if ($savemsg) {
    print_info_box($savemsg, 'success');
}
?>
<div class="panel panel-default">
  <div class="panel-heading"><h2 class="panel-title"><?=gettext('Fail2Ban Guard receiver')?></h2></div>
  <div class="panel-body">
    <p class="help-block"><?=gettext('The package is disabled until explicitly enabled. It accepts HTTPS mTLS events and updates only the package-owned PF tables.')?></p>
    <form method="post" action="f2bguard.php" autocomplete="off">
      <input type="hidden" name="action" value="save" />
      <div class="form-group">
        <label><input type="checkbox" name="enabled" value="1" <?=$cfg['enabled'] ? 'checked="checked"' : ''?> /> <?=gettext('Enable Fail2Ban Guard')?></label>
        <p class="help-block"><?=gettext('Enabling starts the separate backend and privileged PF helper after validation.')?></p>
      </div>
      <div class="form-group">
        <label for="listen"><?=gettext('Listen address')?></label>
        <input id="listen" name="listen" class="form-control" type="text" value="<?=f2bguard_html($cfg['listen'])?>" required="required" />
        <p class="help-block"><?=gettext('One explicit local IPv4 or IPv6 address. Wildcard addresses are rejected.')?></p>
      </div>
      <div class="form-group">
        <label for="port"><?=gettext('HTTPS port')?></label>
        <input id="port" name="port" class="form-control" type="number" min="1024" max="65535" value="<?=f2bguard_html($cfg['port'])?>" required="required" />
      </div>
      <div class="row">
        <div class="col-sm-6 form-group">
          <label for="tls_cert_ref"><?=gettext('Server certificate')?></label>
          <select id="tls_cert_ref" name="tls_cert_ref" class="form-control">
<?php foreach (f2bguard_certificate_choices('cert') as $ref => $label): ?>
            <option value="<?=f2bguard_html($ref)?>" <?=$ref === (string)array_get_path($cfg, 'tls_cert_ref', '') ? 'selected="selected"' : ''?>><?=f2bguard_html($label)?></option>
<?php endforeach; ?>
          </select>
          <p class="help-block"><?=gettext('Select a certificate and private key managed by System > Cert. Manager.')?></p>
        </div>
        <div class="col-sm-6 form-group">
          <label for="tls_ca_ref"><?=gettext('Trusted client CA')?></label>
          <select id="tls_ca_ref" name="tls_ca_ref" class="form-control">
<?php foreach (f2bguard_certificate_choices('ca') as $ref => $label): ?>
            <option value="<?=f2bguard_html($ref)?>" <?=$ref === (string)array_get_path($cfg, 'tls_ca_ref', '') ? 'selected="selected"' : ''?>><?=f2bguard_html($label)?></option>
<?php endforeach; ?>
          </select>
          <p class="help-block"><?=gettext('Only clients signed by this CA and listed on the Clients tab are accepted.')?></p>
        </div>
      </div>
      <div class="form-group">
        <label for="whitelist_alias"><?=gettext('Whitelist alias')?></label>
        <select id="whitelist_alias" name="whitelist_alias" class="form-control">
          <option value=""><?=gettext('No whitelist alias')?></option>
<?php foreach (f2bguard_get_aliases() as $name => $label): ?>
          <option value="<?=f2bguard_html($name)?>" <?=$name === (string)array_get_path($cfg, 'whitelist_alias', '') ? 'selected="selected"' : ''?>><?=f2bguard_html($name . ' - ' . $label)?></option>
<?php endforeach; ?>
        </select>
        <p class="help-block"><?=gettext('Only literal IP/CIDR entries are accepted. DNS, URL tables, nested aliases, ranges, and failed resolution preserve the last valid snapshot and block new enforcement updates.')?></p>
      </div>
      <div class="form-group">
        <label><?=gettext('WAN interfaces')?></label>
<?php foreach (f2bguard_get_interfaces() as $ifname => $descr): ?>
        <div class="checkbox"><label><input type="checkbox" name="wan_interfaces[]" value="<?=f2bguard_html($ifname)?>" <?=in_array($ifname, $selected_interfaces, true) ? 'checked="checked"' : ''?> /> <?=f2bguard_html($descr)?> <small>(<?=f2bguard_html($ifname)?>)</small></label></div>
<?php endforeach; ?>
        <p class="help-block"><?=gettext('Generated PF rules block banned sources entering these interfaces. The backend and helper own the table contents.')?></p>
      </div>
      <fieldset><legend><?=gettext('Limits and history')?></legend>
<?php foreach (f2bguard_limit_specs() as $key => $spec): ?>
        <div class="form-group"><label for="<?=f2bguard_html($key)?>"><?=f2bguard_html($spec[3])?></label>
          <input class="form-control" type="number" id="<?=f2bguard_html($key)?>" name="<?=f2bguard_html($key)?>" min="<?=$spec[1]?>" max="<?=$spec[2]?>" value="<?=f2bguard_html(array_get_path($cfg, 'limits/' . $key, $spec[0]))?>" required="required" />
        </div>
<?php endforeach; ?>
        <div class="form-group"><label for="history_days"><?=gettext('History retention in days')?></label>
          <input class="form-control" type="number" id="history_days" name="history_days" min="1" max="3650" value="<?=f2bguard_html($cfg['history_days'])?>" required="required" />
          <p class="help-block"><?=gettext('History never causes automatic blocking. Active Fail2Ban claims remain until released.')?></p>
        </div>
      </fieldset>
      <button type="submit" class="btn btn-primary"><?=gettext('Save')?></button>
    </form>
  </div>
</div>
<?php include('foot.inc'); ?>

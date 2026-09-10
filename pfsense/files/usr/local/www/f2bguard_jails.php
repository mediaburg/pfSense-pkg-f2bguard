<?php
require_once('guiconfig.inc');
require_once('/usr/local/pkg/f2bguard.inc');

$cfg = f2bguard_get_config();
$jails = array_values(array_filter((array)array_get_path($cfg, 'jails', array()), function ($jail) {
    return is_string($jail) && preg_match('/^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$/', $jail);
}));
$input_errors = array();
$savemsg = '';
if ($_POST) {
    $action = (string)($_POST['action'] ?? '');
    if ($action === 'save') {
        $jail = trim((string)($_POST['jail'] ?? ''));
        f2bguard_validate_identifier($jail, gettext('Jail'), $input_errors);
        if (in_array($jail, $jails, true)) {
            $input_errors[] = gettext('Jail is already configured.');
        }
        if (empty($input_errors)) {
            $jails[] = $jail;
            sort($jails, SORT_NATURAL | SORT_FLAG_CASE);
            $cfg['jails'] = $jails;
            if (f2bguard_store_config($cfg, gettext('Added a Fail2Ban Guard jail.'))) {
                if (f2bguard_resync_config(true)) {
                    $savemsg = gettext('Jail added.');
                } else {
                    $input_errors[] = $GLOBALS['f2bguard_last_error'] ?? gettext('Runtime configuration could not be applied.');
                }
            } else {
                $input_errors[] = gettext('Unable to save the pfSense configuration.');
            }
        }
    } elseif ($action === 'delete') {
        $jail = trim((string)($_POST['jail'] ?? ''));
        $jails = array_values(array_filter($jails, function ($item) use ($jail) { return $item !== $jail; }));
        $cfg['jails'] = $jails;
        if (f2bguard_store_config($cfg, gettext('Removed a Fail2Ban Guard jail.'))) {
            if (f2bguard_resync_config(true)) {
                $savemsg = gettext('Jail removed. Existing client permissions were retained; review them on the Clients tab.');
            } else {
                $input_errors[] = $GLOBALS['f2bguard_last_error'] ?? gettext('Runtime configuration could not be applied.');
            }
        } else {
            $input_errors[] = gettext('Unable to save the pfSense configuration.');
        }
    }
}
$pgtitle = array(gettext('Services'), gettext('Fail2Ban Guard'), gettext('Jails'));
$pglinks = array('', '/f2bguard.php', '@self');
include('head.inc');
f2bguard_render_tabs('jails');
if ($input_errors) {
    print_input_errors($input_errors);
}
if ($savemsg) {
    print_info_box($savemsg, 'success');
}
?>
<div class="panel panel-default"><div class="panel-heading"><h2 class="panel-title"><?=gettext('Allowed jail identifiers')?></h2></div><div class="panel-body">
<p class="help-block"><?=gettext('These identifiers document the jails accepted by this installation. Client permissions are configured separately. The package never invents or replays claims for a jail.')?></p>
<form method="post" action="f2bguard_jails.php" class="form-inline"><input type="hidden" name="action" value="save" /><label for="jail" class="sr-only"><?=gettext('Jail identifier')?></label><input id="jail" name="jail" class="form-control" placeholder="recidive" required="required" /><button type="submit" class="btn btn-primary"><?=gettext('Add jail')?></button></form>
</div></div>
<div class="panel panel-default"><div class="panel-heading"><h2 class="panel-title"><?=gettext('Configured jails')?></h2></div><div class="panel-body table-responsive"><table class="table table-striped"><thead><tr><th><?=gettext('Jail')?></th><th><?=gettext('Action')?></th></tr></thead><tbody>
<?php foreach ($jails as $jail): ?><tr><td><code><?=f2bguard_html($jail)?></code></td><td><form method="post" action="f2bguard_jails.php"><input type="hidden" name="action" value="delete" /><input type="hidden" name="jail" value="<?=f2bguard_html($jail)?>" /><button type="submit" class="btn btn-xs btn-danger"><?=gettext('Delete')?></button></form></td></tr><?php endforeach; ?>
<?php if (!$jails): ?><tr><td colspan="2"><?=gettext('No jails configured.')?></td></tr><?php endif; ?>
</tbody></table></div></div>
<?php include('foot.inc'); ?>

<?php

$priv_list['page-services-f2bguard'] = array();
$priv_list['page-services-f2bguard']['name'] = gettext('WebCfg - Services: Fail2Ban Guard');
$priv_list['page-services-f2bguard']['descr'] = gettext('Allow access to the Fail2Ban Guard package pages.');
$priv_list['page-services-f2bguard']['match'] = array();
$priv_list['page-services-f2bguard']['match'][] = 'f2bguard.php*';
$priv_list['page-services-f2bguard']['match'][] = 'f2bguard_clients.php*';
$priv_list['page-services-f2bguard']['match'][] = 'f2bguard_jails.php*';
$priv_list['page-services-f2bguard']['match'][] = 'f2bguard_status.php*';

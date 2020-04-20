<?php
/**
 * Action to reset a password, send success email, and log the user in.
 *
 * @package Elgg
 * @subpackage Core
 */

$password = get_input('password1', null, false);
$password_repeat = get_input('password2', null, false);
$user_guid = get_input('u');
$code = get_input('c');

try {
	validate_password($password);
} catch(RegistrationException $e) {
	register_error($e->getMessage());
	forward(REFERER);
}

if ($password != $password_repeat) {
	register_error(elgg_echo('RegistrationException:PasswordMismatch'));
	forward(REFERER);
}

$execute_new_password_request = function($user_guid, $conf_code, $password) {
    $user_guid = (int)$user_guid;
    $user = get_entity($user_guid);

    if ($password === null) {
        $password = generate_random_cleartext_password();
        $reset = true;
    } else {
        $reset = false;
    }

    if (!$user instanceof \ElggUser) {
        return false;
    }

    $saved_code = $user->getPrivateSetting('passwd_conf_code');
    $code_time = (int) $user->getPrivateSetting('passwd_conf_time');
    $codes_match = _elgg_services()->crypto->areEqual($saved_code, $conf_code);

    if (!$saved_code || !$codes_match) {
        return false;
    }

    // Discard for security if it is 24h old
    if (!$code_time || $code_time < time() - 24 * 60 * 60) {
        return false;
    }

    $hash = _elgg_services()->passwords->generateHash($password);
    $dbprefix = elgg_get_config('dbprefix');
    update_data("UPDATE {$dbprefix}users_entity SET password_hash = :pw WHERE guid = :guid", [':pw' => $hash, ':guid' => $user->guid]);

    remove_private_setting($user_guid, 'passwd_conf_code');
    remove_private_setting($user_guid, 'passwd_conf_time');
    // clean the logins failures
    reset_login_failure_count($user_guid);

    $ns = $reset ? 'resetpassword' : 'changepassword';

    $message = _elgg_services()->translator->translate(
        "email:$ns:body", array($user->username, $password), $user->language);
    $subject = _elgg_services()->translator->translate("email:$ns:subject", array(), $user->language);

    $params = [
        'action' => $ns,
        'object' => $user,
        'password' => $password,
    ];

    notify_user($user->guid, elgg_get_site_entity()->guid, $subject, $message, $params, 'email');

    return true;
};

if ($execute_new_password_request($user_guid, $code, $password)) {
	system_message(elgg_echo('user:password:success'));
	
	try {
		login(get_entity($user_guid));
	} catch (LoginException $e) {
		register_error($e->getMessage());
		forward(REFERER);
	}
} else {
	register_error(elgg_echo('user:password:fail'));
}

forward();


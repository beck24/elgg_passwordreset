<?php

elgg_register_event_handler('init', 'system', function() {
    elgg_register_action('user/changepassword', __DIR__ . '/actions/changepassword.php', 'public');
});
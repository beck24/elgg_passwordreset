# elgg_passwordreset
Fixes an issue with password reset in legacy elgg 2.3 where:

1. Certain special characters were encoded improperly making the password impossible to use
2. Certain passwords would simply not update

This bypasses the core elgg password reset using the entity save API and updates the password_hash in a direct query.
-- Add migration script here
update config set key = 'FirewallConfigVersion' where key = 'Version'
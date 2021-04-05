-- Add migration script here
ALTER TABLE devices ALTER COLUMN ip_addr DROP NOT NULL;
ALTER TABLE devices RENAME COLUMN ip_addr TO ipv4_addr;
ALTER TABLE devices ADD CONSTRAINT devices_ipv4_addr_key UNIQUE(ipv4_addr);
ALTER TABLE devices ADD COLUMN ipv6_addr TEXT UNIQUE;
ALTER TABLE devices ADD COLUMN name TEXT;
ALTER TABLE devices ADD COLUMN duid TEXT;
ALTER TABLE devices ADD CONSTRAINT devices_mac_addr_duid_key UNIQUE (mac_addr, duid);

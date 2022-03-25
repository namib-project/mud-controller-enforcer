#!/usr/bin/env bash

set -e

# This adds 3 users admin, read and new_user all with password "namibnamib"

function import() {
  local CMD=$1
  $CMD <<'EOF'
  INSERT OR REPLACE INTO floors(id, label) VALUES (1, '1st floor');
  INSERT INTO rooms (number, floor_id) VALUES
    ('100', 1),
    ('101', 1);
  INSERT INTO mud_data (url, data, created_at, expiration) VALUES
    ('https://gitlab.freedesktop.org/sw0rd/MUD-Files/-/raw/master/amazonEchoMud.json', '{}', '2021-03-27T14:20:00', '1970-01-01T00:00:00'),
    ('https://gitlab.freedesktop.org/sw0rd/MUD-Files/-/raw/master/augustdoorbellcamMud.json', '{}', '2021-03-27T14:20:00', '1970-01-01T00:00:00'),
    ('https://gitlab.freedesktop.org/sw0rd/MUD-Files/-/raw/master/belkincameraMud.json', '{}', '2021-03-27T14:20:00', '1970-01-01T00:00:00');
  INSERT INTO devices (ipv4_addr, mac_addr, hostname, vendor_class, mud_url, last_interaction, collect_info) VALUES
    ('192.168.1.101', '2b:7d:c4:83:85:1e', 'Device 1', 'Manufacturer 1', 'https://gitlab.freedesktop.org/sw0rd/MUD-Files/-/raw/master/amazonEchoMud.json', '2021-03-27T14:20:00', false),
    ('192.168.1.102', '7d:1a:51:55:5a:4e', 'Device 2', 'Manufacturer 2', 'https://gitlab.freedesktop.org/sw0rd/MUD-Files/-/raw/master/augustdoorbellcamMud.json', '2021-03-26T16:43:00', false),
    ('192.168.1.103', 'a3:89:dd:c0:41:6e', 'Device 3', '', NULL, '2021-03-25T16:43:00', true),
    ('192.168.1.104', 'e3:0e:d6:03:92:c3', 'Device 4', 'Manufacturer 1', NULL, '2021-03-24T16:43:00', false),
    ('192.168.1.105', 'ce:cf:88:01:2c:2e', 'Device 5', 'Manufacturer 3', 'https://gitlab.freedesktop.org/sw0rd/MUD-Files/-/raw/master/amazonEchoMud.json', '2021-03-27T14:20:00', false),
    ('192.168.1.106', 'b1:3a:ba:55:56:62', 'Device 6', 'Manufacturer 4', 'https://gitlab.freedesktop.org/sw0rd/MUD-Files/-/raw/master/belkincameraMud.json', '2021-03-27T14:20:00', false),
    ('192.168.1.107', '0c:24:3d:50:6d:fe', 'Device 7', 'Manufacturer 4', 'https://gitlab.freedesktop.org/sw0rd/MUD-Files/-/raw/master/amazonEchoMud.json', '2021-03-27T14:20:00', false),
    ('192.168.1.108', '25:f0:f0:0c:20:28', 'Device 8', 'Manufacturer 5', 'https://gitlab.freedesktop.org/sw0rd/MUD-Files/-/raw/master/amazonEchoMud.json', '2021-03-27T14:20:00', false),
    ('192.168.1.109', '25:f0:f0:0c:20:29', 'Device 9', 'Manufacturer 6', 'https://gitlab.freedesktop.org/sw0rd/MUD-Files/-/raw/master/amazonEchoMud.json', '2021-03-27T14:20:00', false),
    ('192.168.1.110', '25:f0:f0:0c:20:30', 'Device 10', 'Manufacturer 7', 'https://gitlab.freedesktop.org/sw0rd/MUD-Files/-/raw/master/amazonEchoMud.json', '2021-03-27T14:20:00', false),
    ('192.168.1.111', '25:f0:f0:0c:20:31', 'Device 11', 'Manufacturer 8', 'https://gitlab.freedesktop.org/sw0rd/MUD-Files/-/raw/master/amazonEchoMud.json', '2021-03-27T14:20:00', false),
    ('192.168.1.112', '25:f0:f0:0c:20:32', 'Device 12', 'Manufacturer 9', 'https://gitlab.freedesktop.org/sw0rd/MUD-Files/-/raw/master/amazonEchoMud.json', '2021-03-27T14:20:00', false),
    ('192.168.1.113', '25:f0:f0:0c:20:33', 'Device 13', 'Manufacturer 10', 'https://gitlab.freedesktop.org/sw0rd/MUD-Files/-/raw/master/belkincameraMud.json', '2021-03-27T14:20:00', false),
    ('192.168.1.114', '25:f0:f0:0c:20:34', 'Device 14', 'Manufacturer 11', 'https://gitlab.freedesktop.org/sw0rd/MUD-Files/-/raw/master/augustdoorbellcamMud.json', '2021-03-27T14:20:00', false),
    ('192.168.1.115', '25:f0:f0:0c:20:35', 'Device 15', 'Manufacturer 12', 'https://gitlab.freedesktop.org/sw0rd/MUD-Files/-/raw/master/augustdoorbellcamMud.json', '2021-03-27T14:20:00', false);
  UPDATE devices SET room_id = (SELECT room_id FROM rooms WHERE number = '100') WHERE mac_addr = '2b:7d:c4:83:85:1e';
  UPDATE devices SET room_id = (SELECT room_id FROM rooms WHERE number = '101') WHERE mac_addr = '7d:1a:51:55:5a:4e';
  UPDATE devices SET room_id = (SELECT room_id FROM rooms WHERE number = '100') WHERE mac_addr = 'ce:cf:88:01:2c:2e';
  UPDATE devices SET room_id = (SELECT room_id FROM rooms WHERE number = '101') WHERE mac_addr = 'b1:3a:ba:55:56:62';
  INSERT INTO users (username, password, salt) VALUES
    ('admin', '$argon2i$v=19$m=4096,t=3,p=1$SOG5O7ZAUZ6elXQZMHF55K7KUjftvXqQwWS1SUhJKW0$eyE76g3JUALKvM5xgsccQhh8fB1hsRV4pIeWxVOtl8M', '48E1B93BB640519E9E957419307179E4AECA5237EDBD7A90C164B5494849296D'),
    ('reader', '$argon2i$v=19$m=4096,t=3,p=1$OP4TABHMAKSSP5re6J7ciiuI58u9iWSKBoVv2m55bMA$P+0/apaZHvO1zuF8T1pvrts9YR8zzuKUxs+IlZHodpU', '38FE130011CC00A4923F9ADEE89EDC8A2B88E7CBBD89648A06856FDA6E796CC0'),
    ('new_user', '$argon2i$v=19$m=4096,t=3,p=1$rPM6iG4Y71r48MH1wxuONL28JHMzVHYqqcCTDXbQJTw$ILQ51sciAxbQqKQLDS6B6wrTnblhl6+d4QI+Kc7Ik6k', 'ACF33A886E18EF5AF8F0C1F5C31B8E34BDBC24733354762AA9C0930D76D0253C');
  INSERT INTO users_roles (user_id, role_id) SELECT id, 0 FROM users WHERE username = 'admin';
  INSERT INTO users_roles (user_id, role_id) SELECT id, 1 FROM users WHERE username = 'reader';
EOF
  echo "INFO: mock data import finished."
}

if [ "$1" == "docker" ]; then
  if [ -f "db.sqlite" ]; then
    import "sqlite3 db.sqlite"
  else
    import "psql postgresql://namib:namib@postgres/namib_mud_controller"
  fi
  exit
fi

echo "What execution method are you using?"
echo "0) SQlite"
echo "1) PostgreSQL"
echo "2) Docker (default)"

read -p "> " EXEC_METHOD

case $EXEC_METHOD in
  0)
    import "sqlite3 db.sqlite"
    ;;
  1)
    import "psql postgresql://namib:namib@localhost/namib_mud_controller"
    ;;
  *)
    DOCK_ID=$(docker ps | awk '/gitlab.informatik.uni-bremen.de:5005\/namib\/mud-controller-enforcer\/namib_mud_controller/{print $1}')
    cat $0 | docker exec -i $DOCK_ID bash -s - docker
    ;;
esac

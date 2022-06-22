
CREATE TABLE device_connections (
  device_id INTEGER NOT NULL,
  date TIMESTAMP NOT NULL,
  direction INTEGER NOT NULL,
  target    TEXT NOT NULL,
  amount    INTEGER NOT NULL,
  PRIMARY KEY (device_id, direction, target)
);

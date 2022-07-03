
CREATE TABLE device_connections (
  device_id BIGSERIAL NOT NULL,
  date TIMESTAMP NOT NULL,
  direction BIGSERIAL NOT NULL,
  target    TEXT NOT NULL,
  amount    BIGSERIAL NOT NULL,
  PRIMARY KEY (device_id, direction, target, date)
);

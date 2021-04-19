insert into roles (id, name, permissions) VALUES (0, 'admin', '**'), (1, 'reader', '**/list,**/read');
alter sequence roles_id_seq start with 2;
alter sequence roles_id_seq restart;
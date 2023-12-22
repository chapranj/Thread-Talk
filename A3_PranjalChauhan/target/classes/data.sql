insert into users(username, password,  enabled) values ('chapranj','$2a$10$6y/QQ19Kkg90WgWFN2YGdup2zA/NN4YYcTNNida1mDxcJt8wKYyhq', TRUE);
insert into users(username, password,  enabled) values ('masterha','$2a$10$6y/QQ19Kkg90WgWFN2YGdup2zA/NN4YYcTNNida1mDxcJt8wKYyhq', TRUE);

insert into authorities(username, authority) values ('chapranj','ROLE_USER');
insert into authorities(username, authority) values ('masterha','ROLE_USER');

insert into users(username, password, enabled) values ('nikolai','$2a$10$ItjMm7lWMDR1/Fjm43YzJOskyjkYGjl2873i8HnIgGMtHfDa3A7b6', TRUE);

insert into authorities(username, authority) values ('nikolai','ROLE_USER');

insert into authorities(username, authority) values ('nikolai','ROLE_MANAGER');


INSERT INTO threads (title, username) VALUES
('General Discussion', 'chapranj'),
('Technical Support', 'nikolai'),
('Programming Help', 'nikolai');


INSERT INTO posts (content, threadId, username) VALUES
('Hello, everyone! Welcome to the general discussion.', 1, 'chapranj'),
('Im excited to be part of this community!', 1, 'nikolai'),
('Having trouble with my internet connection. Any suggestions?', 2, 'chapranj'),
('Check if your router is working properly.', 2, 'nikolai'),
('Im getting a syntax error in my Java code. Can someone help?', 3, 'masterha'),
('Sure, post your code, and we will try to help!', 3, 'nikolai');
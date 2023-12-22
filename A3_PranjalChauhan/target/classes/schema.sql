--ALTER TABLE IF EXISTS authorities DROP FOREIGN KEY IF EXISTS fk_authorities_users;
--ALTER TABLE IF EXISTS threads DROP FOREIGN KEY IF EXISTS fk_threads_users;
--ALTER TABLE IF EXISTS posts DROP FOREIGN KEY IF EXISTS fk_posts_threads;
--ALTER TABLE IF EXISTS posts DROP FOREIGN KEY IF EXISTS fk_posts_users;

-- Drop tables in the correct order
DROP TABLE IF EXISTS posts;
DROP TABLE IF EXISTS threads;
DROP TABLE IF EXISTS authorities;
DROP TABLE IF EXISTS users;

create table users(
	username varchar(50) not null primary key,
	password varchar(120) not null,
	enabled boolean not null
);

create table authorities(
	username varchar(50) not null,
	authority varchar(50) not null,
	foreign key (username) references users (username)
);

create table threads(
	threadId int primary key auto_increment,
	title varchar(255) not null,
	username varchar(50),
	foreign key (username) references users(username)
);

create table posts(
	postId int primary key auto_increment,
	content text not null,
	date timestamp default CURRENT_TIMESTAMP,
	threadId int,
	username varchar (50),
	foreign key (threadId) references threads(threadId) ON DELETE CASCADE,
	foreign key (username) references users(username)
);
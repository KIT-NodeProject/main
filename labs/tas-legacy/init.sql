CREATE DATABASE IF NOT EXISTS board;
USE board;

CREATE TABLE IF NOT EXISTS list (
    id INT AUTO_INCREMENT PRIMARY KEY,
    title VARCHAR(255) NOT NULL,
    name VARCHAR(100) NOT NULL,
    content TEXT,
    post_date DATETIME DEFAULT CURRENT_TIMESTAMP,
    filename VARCHAR(255)
);

INSERT INTO list (id, title, name, content, filename) VALUES (1, 'first_content.', 'admin', 'content_test.', NULL);

ALTER TABLE list AUTO_INCREMENT = 2;

CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(100) NOT NULL,
    user_id VARCHAR(100) NOT NULL,
    user_password VARCHAR(255) NOT NULL
);

INSERT INTO users (id, username, user_id, user_password) VALUES (1, 'guest', 'guest', 'guest');
INSERT INTO users (id, username, user_id, user_password) VALUES (2, 'admin', 'admin', 'aineunvoidjrinowaodiejnvnv');

ALTER TABLE users AUTO_INCREMENT = 3;

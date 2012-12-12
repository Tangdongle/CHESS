CREATE TABLE ohms_users(
    userid MEDIUMINT NOT NULL AUTO_INCREMENT,
    username VARCHAR(30),
    password VARCHAR(64),
    privilege INT,
    primary key (userid)
);

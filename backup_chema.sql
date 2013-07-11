CREATE DATABASE IF NOT EXISTS chess;
USE chess;

DROP TABLE IF EXISTS chess_incidents;
DROP TABLE IF EXISTS password_change_requests;
DROP TABLE IF EXISTS chess_reports;
DROP TABLE IF EXISTS chess_locations;
DROP TABLE IF EXISTS chess_users;

CREATE TABLE chess_users(
    id INT unsigned NOT NULL AUTO_INCREMENT,
    username VARCHAR(30) NOT NULL UNIQUE,
    password VARCHAR(64),
    email VARCHAR(64),
    privilege INT,
    PRIMARY KEY (id)
)ENGINE=InnoDB;

CREATE TABLE password_change_requests(
    id INT unsigned NOT NULL AUTO_INCREMENT,
    FK_userid INT unsigned NOT NULL,
    userkey VARCHAR(128) NOT NULL,
    timestamp INT unsigned,
    INDEX (FK_userid),
    FOREIGN KEY (FK_userid) REFERENCES chess_users(id)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    PRIMARY KEY (id)
)ENGINE=InnoDB;

CREATE TABLE chess_reports(
    id INT unsigned NOT NULL AUTO_INCREMENT,
    report_text TEXT NOT NULL,
    people_involved TEXT,
    PRIMARY KEY (id)
)ENGINE=InnoDB;

CREATE TABLE chess_locations(
    id INT unsigned NOT NULL AUTO_INCREMENT,
    country VARCHAR(64) NOT NULL,
    state VARCHAR(64) NOT NULL,
    site VARCHAR(128) NOT NULL,
    section VARCHAR(128),
    PRIMARY KEY (id),
    UNIQUE INDEX COUNTRY_INDEX (country,state,site)
)ENGINE=InnoDB;

CREATE TABLE chess_incidents(
    id INT unsigned NOT NULL AUTO_INCREMENT,
    FK_userid INT unsigned NOT NULL,
    FK_reportid INT unsigned NOT NULL,
    FK_locationid INT unsigned NOT NULL,
    timestamp INT unsigned,
    INDEX (FK_userid),
    FOREIGN KEY (FK_userid) REFERENCES chess_users(id) 
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    INDEX (FK_reportid),
    FOREIGN KEY (FK_reportid) REFERENCES chess_reports(id)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    INDEX (FK_locationid),
    FOREIGN KEY (FK_locationid) REFERENCES chess_locations(id)
        ON UPDATE CASCADE ON DELETE RESTRICT,
    PRIMARY KEY (id)
)ENGINE=InnoDB;

INSERT INTO chess_users VALUES ('fiddle','fiddle');


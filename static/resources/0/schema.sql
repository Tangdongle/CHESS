CREATE DATABASE IF NOT EXISTS chess;
USE chess;

DROP TABLE IF EXISTS chess_resources;
DROP TABLE IF EXISTS chess_resourcetypes;
DROP TABLE IF EXISTS password_change_requests;
DROP TABLE IF EXISTS chess_users;
DROP TABLE IF EXISTS chess_clients;


CREATE TABLE chess_clients(
    clientID INT UNSIGNED NOT NULL,
    clientname VARCHAR(128) NOT NULL,
    PRIMARY KEY (clientID)
)ENGINE=InnoDB;

CREATE TABLE chess_users(
    userID INT UNSIGNED NOT NULL AUTO_INCREMENT, 
    FK_clientID INT UNSIGNED NOT NULL,
    username VARCHAR(30) NOT NULL,
    password VARCHAR(64) NOT NULL,
    email VARCHAR(64),
    privilege INT DEFAULT 0,
    PRIMARY KEY (userID, FK_clientID),
    FOREIGN KEY (FK_clientID) REFERENCES chess_clients(clientID)
        ON UPDATE RESTRICT ON DELETE RESTRICT
)ENGINE=InnoDB;

CREATE TABLE password_change_requests(
    FK_clientID INT UNSIGNED NOT NULL,
    FK_userID INT UNSIGNED NOT NULL,
    userkey VARCHAR(128) NOT NULL,
    timestamp INT UNSIGNED,
    FOREIGN KEY (FK_userID) REFERENCES chess_users(userID)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    FOREIGN KEY (FK_clientID) REFERENCES chess_clients(clientID)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    PRIMARY KEY (FK_clientID, FK_userID)
)ENGINE=InnoDB;

CREATE TABLE chess_resourcetypes(
    resourceID INT UNSIGNED NOT NULL AUTO_INCREMENT,
    resourcetype VARCHAR(255) NOT NULL,
    resourcecat VARCHAR(255) NOT NULL,
    resourcefname VARCHAR(255) NOT NULL,
    requiredpriv INT UNSIGNED DEFAULT 0,
    PRIMARY KEY (resourceID)
)ENGINE=InnoDB;

CREATE TABLE chess_resources(
    FK_clientID INT UNSIGNED NOT NULL,
    FK_resourceID INT UNSIGNED NOT NULL,
    FOREIGN KEY (FK_clientID) REFERENCES chess_clients(clientID)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    FOREIGN KEY (FK_resourceID) REFERENCES chess_resourcetypes(resourceID)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    PRIMARY KEY (FK_clientID, FK_resourceID)
)ENGINE=InnoDB;

INSERT INTO chess_clients VALUES (69,"J&R Co.");
INSERT INTO chess_resourcetypes VALUES ("script","python","socktest.py");

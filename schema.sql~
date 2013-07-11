DROP DATABASE IF EXISTS chess;
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
    FK_clientID INT UNSIGNED NOT NULL,
    resourcetype VARCHAR(255) NOT NULL,
    resourcecat VARCHAR(255) NOT NULL,
    resourcefname VARCHAR(255) NOT NULL,
    requiredpriv INT UNSIGNED DEFAULT 0,
    PRIMARY KEY (resourceID),
    FOREIGN KEY (FK_clientID) REFERENCES chess_clients(clientID)
        ON UPDATE RESTRICT ON DELETE RESTRICT
)ENGINE=InnoDB;

CREATE TABLE chess_repository(
    repoID INT UNSIGNED NOT NULL AUTO_INCREMENT,
    FK_clientID INT UNSIGNED NOT NULL,
    resourcefname VARCHAR(255) NOT NULL,
    mod_timestamp INT UNSIGNED NOT NULL,
    is_latest BOOLEAN DEFAULT false,
    PRIMARY KEY(repoID),
    FOREIGN KEY (FK_clientID) REFERENCES chess_clients(clientID)
        ON UPDATE RESTRICT ON DELETE RESTRICT
)ENGINE=InnoDB;

INSERT INTO chess_clients VALUES (69,"J&R Co.");
INSERT INTO chess_clients VALUES (000,"Admin");

INSERT INTO chess_users (FK_clientID, username, password, email,privilege) VALUES (0, 'ChessAdmin', '$2a$10$taAjO9O6IPZJvphSSZIIc.hVOVV0WBBoXZbenO1yXG9R1JEFksE6K', 'ryan@skybell.com.au', 99);

INSERT INTO chess_resourcetypes (FK_clientID, resourcetype, resourcecat, resourcefname) VALUES (0, "script","Management System Risk Assessments","schema.sql");
INSERT INTO chess_resourcetypes (FK_clientID, resourcetype, resourcecat, resourcefname) VALUES (0, "script","Management System Registers","site.css");
INSERT INTO chess_resourcetypes (FK_clientID, resourcetype, resourcecat, resourcefname) VALUES (0, "document","Management System Policies","schinky.txt");
INSERT INTO chess_resourcetypes (FK_clientID, resourcetype, resourcecat, resourcefname) VALUES (0, "document","Management System Plans","Documentation.doc");
INSERT INTO chess_resourcetypes (FK_clientID, resourcetype, resourcecat, resourcefname) VALUES (0, "script","Management System Forms","socktest.py");
INSERT INTO chess_resourcetypes (FK_clientID, resourcetype, resourcecat, resourcefname) VALUES (0, "script","JHAs-JSAs-SWMS","schema.sql");
INSERT INTO chess_resourcetypes (FK_clientID, resourcetype, resourcecat, resourcefname) VALUES (0, "script","Pre-qualification or Pre-registration","site.css");
INSERT INTO chess_resourcetypes (FK_clientID, resourcetype, resourcecat, resourcefname) VALUES (0, "document","Tender Requirements for Projects","schinky.txt");
INSERT INTO chess_resourcetypes (FK_clientID, resourcetype, resourcecat, resourcefname) VALUES (0, "document","Project Documents","Documentation.doc");
INSERT INTO chess_resourcetypes (FK_clientID, resourcetype, resourcecat, resourcefname) VALUES (0, "document","Audits - Internal or Third Party","Documentation.doc");
INSERT INTO chess_resourcetypes (FK_clientID, resourcetype, resourcecat, resourcefname) VALUES (0, "document","Accreditation of OHS management systems","Documentation.doc");
INSERT INTO chess_resourcetypes (FK_clientID, resourcetype, resourcecat, resourcefname) VALUES (0, "document","Human Resources","Documentation.doc");
INSERT INTO chess_resourcetypes (FK_clientID, resourcetype, resourcecat, resourcefname) VALUES (0, "document","Management System Library","Documentation.doc");
INSERT INTO chess_resourcetypes (FK_clientID, resourcetype, resourcecat, resourcefname) VALUES (0, "script","Contractors","socktest.py");
INSERT INTO chess_resourcetypes (FK_clientID, resourcetype, resourcecat, resourcefname) VALUES (0, "document","Archive","Documentation.doc");

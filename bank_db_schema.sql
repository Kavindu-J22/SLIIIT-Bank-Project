CREATE DATABASE IF NOT EXISTS bank_db;
USE bank_db;

CREATE TABLE IF NOT EXISTS user (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(255) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    role ENUM('CUSTOMER', 'STAFF', 'ADMIN') NOT NULL
);

CREATE TABLE IF NOT EXISTS account (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    account_number VARCHAR(255) UNIQUE NOT NULL,
    account_type ENUM('SAVINGS', 'CURRENT') NOT NULL,
    balance DOUBLE NOT NULL,
    full_name VARCHAR(255) NOT NULL,
    date_of_birth DATE NOT NULL,
    address VARCHAR(255) NOT NULL,
    user_id BIGINT,
    FOREIGN KEY (user_id) REFERENCES user(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS transaction (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    amount DOUBLE NOT NULL,
    type ENUM('DEPOSIT', 'WITHDRAWAL', 'TRANSFER') NOT NULL,
    date DATETIME NOT NULL,
    description VARCHAR(255),
    from_account_id BIGINT,
    to_account_id BIGINT,
    FOREIGN KEY (from_account_id) REFERENCES account(id),
    FOREIGN KEY (to_account_id) REFERENCES account(id)
);

CREATE TABLE IF NOT EXISTS loan (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    loan_type VARCHAR(255) NOT NULL,
    amount DOUBLE NOT NULL,
    duration INT NOT NULL,
    status ENUM('PENDING', 'IN_REVIEW', 'APPROVED', 'REJECTED') NOT NULL,
    applicant_id BIGINT NOT NULL,
    reviewer_id BIGINT,
    approver_id BIGINT,
    FOREIGN KEY (applicant_id) REFERENCES user(id),
    FOREIGN KEY (reviewer_id) REFERENCES user(id),
    FOREIGN KEY (approver_id) REFERENCES user(id)
);

CREATE TABLE IF NOT EXISTS feedback (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    subject VARCHAR(255) NOT NULL,
    message TEXT NOT NULL,
    status ENUM('OPEN', 'IN_PROGRESS', 'RESOLVED') NOT NULL,
    reply TEXT,
    customer_id BIGINT NOT NULL,
    staff_id BIGINT,
    FOREIGN KEY (customer_id) REFERENCES user(id),
    FOREIGN KEY (staff_id) REFERENCES user(id)
);
CREATE DATABASE IF NOT EXISTS Medical_Managment
CHARACTER SET utf8mb4
COLLATE utf8mb4_unicode_ci;
USE Medical_Management;

CREATE DATABASE IF NOT EXISTS Medical_Management
CHARACTER SET utf8mb4
COLLATE utf8mb4_unicode_ci;

USE Medical_Management;

CREATE TABLE IF NOT EXISTS user (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(80) NOT NULL UNIQUE,
    email VARCHAR(120) NOT NULL UNIQUE,
    -- Changed password_hash length from 128 to 255
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(20) NOT NULL DEFAULT 'patient' -- 'patient', 'doctor', 'admin'
);

CREATE TABLE IF NOT EXISTS patient_info (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL UNIQUE,
    full_name VARCHAR(100) NOT NULL,
    date_of_birth DATE,
    gender VARCHAR(10),
    contact_number VARCHAR(20),
    address VARCHAR(200),
    insurance_info VARCHAR(200),
    FOREIGN KEY (user_id) REFERENCES user(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS doctor_info (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL UNIQUE,
    full_name VARCHAR(100) NOT NULL,
    specialty VARCHAR(100),
    contact_number VARCHAR(20),
    clinic_address VARCHAR(200),
    FOREIGN KEY (user_id) REFERENCES user(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS appointment (
    id INT AUTO_INCREMENT PRIMARY KEY,
    patient_id INT NOT NULL,
    doctor_id INT NOT NULL,
    date DATE NOT NULL,
    time VARCHAR(10) NOT NULL, -- Storing as VARCHAR for simplicity as in Python code
    status VARCHAR(20) NOT NULL DEFAULT 'Pending', -- 'Pending', 'Confirmed', 'Completed', 'Cancelled'
    reason TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (patient_id) REFERENCES user(id) ON DELETE CASCADE,
    FOREIGN KEY (doctor_id) REFERENCES user(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS medical_record (
    id INT AUTO_INCREMENT PRIMARY KEY,
    patient_id INT NOT NULL,
    doctor_id INT NOT NULL,
    record_date DATE NOT NULL,
    diagnosis TEXT,
    treatment_notes TEXT,
    lab_results TEXT,
    FOREIGN KEY (patient_id) REFERENCES user(id) ON DELETE CASCADE,
    FOREIGN KEY (doctor_id) REFERENCES user(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS prescription (
    id INT AUTO_INCREMENT PRIMARY KEY,
    patient_id INT NOT NULL,
    doctor_id INT NOT NULL,
    medication VARCHAR(100) NOT NULL,
    dosage VARCHAR(50) NOT NULL,
    instructions TEXT,
    issue_date DATE DEFAULT (CURRENT_DATE()), -- Use CURRENT_DATE() for MySQL
    expiry_date DATE,
    FOREIGN KEY (patient_id) REFERENCES user(id) ON DELETE CASCADE,
    FOREIGN KEY (doctor_id) REFERENCES user(id) ON DELETE CASCADE
);
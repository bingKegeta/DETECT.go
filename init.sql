-- User Table
CREATE TABLE IF NOT EXISTS Users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) NOT NULL UNIQUE,
    password VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    auth_token VARCHAR(255),
    auth_token_created_at TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_users_email ON Users(email);
CREATE INDEX IF NOT EXISTS idx_users_auth_token ON Users(auth_token);

-- Settings Table
CREATE TABLE settings (
    id SERIAL PRIMARY KEY,
    userid INTEGER REFERENCES Users(id),
    sensitivity FLOAT DEFAULT 1.0,
    var_min FLOAT NOT NULL,
    var_max FLOAT NOT NULL,
    acc_min FLOAT NOT NULL,
    acc_max FLOAT NOT NULL,
    plotting BOOLEAN NOT NULL,
    affine BOOLEAN NOT NULL,
    min_max BOOLEAN NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Session Table
CREATE TABLE session (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255),
    user_id INTEGER REFERENCES Users(id),
    start_time TIMESTAMP NOT NULL,
    end_time TIMESTAMP NOT NULL,
    var_min FLOAT NOT NULL,
    var_max FLOAT NOT NULL,
    acc_min FLOAT NOT NULL,
    acc_max FLOAT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Analysis Table
CREATE TABLE analysis (
    id SERIAL PRIMARY KEY,
    session_id INTEGER REFERENCES session(id),
    timestamp FLOAT NOT NULL,
    X FLOAT NOT NULL,
    Y FLOAT NOT NULL,
    prob FLOAT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

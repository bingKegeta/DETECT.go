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

-- WebSocketMessages table to store incoming messages
CREATE TABLE websocket_messages (
    id SERIAL PRIMARY KEY,
    x FLOAT8,
    y FLOAT8,
    second FLOAT8,
    is_video BOOLEAN,
    video_duration FLOAT8
);


-- Index on user_id for faster lookups of messages by user
CREATE INDEX IF NOT EXISTS idx_websocket_messages_user_id ON WebSocketMessages(user_id);

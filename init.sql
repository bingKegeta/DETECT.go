CREATE TABLE Users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) NOT NULL UNIQUE,
    password VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    oauth_provider VARCHAR(50),
    oauth_provider_id VARCHAR(255),
    oauth_token VARCHAR(255),
    oauth_token_expires_at TIMESTAMP,
    CONSTRAINT chk_password_or_oauth CHECK (
            (password IS NOT NULL AND oauth_provider IS NULL AND oauth_provider_id IS NULL) OR
            (password IS NULL AND oauth_provider IS NOT NULL AND oauth_provider_id IS NOT NULL)
        )
);

CREATE INDEX idx_users_email ON Users(email);
CREATE INDEX idx_users_oauth_provider_id ON Users(oauth_provider, oauth_provider_id);

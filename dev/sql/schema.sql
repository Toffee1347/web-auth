CREATE OR REPLACE FUNCTION update_last_updated_column() 
RETURNS TRIGGER AS $$
BEGIN
    NEW.last_updated = now();
    RETURN NEW; 
END;
$$ language 'plpgsql';

-- Should match server/types.d.ts ProfilePictureType
CREATE TYPE profile_picture AS ENUM('custom', 'identicon', 'monsterid', 'wavatar', 'retro', 'robohash');
CREATE TABLE users (
	id UUID NOT NULL PRIMARY KEY,
	username TEXT NOT NULL UNIQUE,
	password TEXT NOT NULL,
	email VARCHAR(256) NOT NULL UNIQUE,
	profile_picture profile_picture NOT NULL DEFAULT 'wavatar',
	created TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
	last_updated TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
	auth_code VARCHAR(7),
	auth_code_expires TIMESTAMP,
	password_reset_token UUID,
	password_reset_token_expires TIMESTAMP,
	admin BOOLEAN NOT NULL DEFAULT FALSE
);
CREATE TRIGGER update_user_last_updated BEFORE UPDATE ON users FOR EACH ROW EXECUTE PROCEDURE update_last_updated_column();

CREATE TABLE sessions (
	id UUID NOT NULL PRIMARY KEY,
	ip INET NOT NULL,
	expires TIMESTAMP NOT NULL,
	user_id UUID REFERENCES users (id),
	wait_for_auth_user_id UUID REFERENCES users (id)
);

CREATE TABLE ouath2_codes (
	code CHAR(50) NOT NULL PRIMARY KEY,
	user_id UUID REFERENCES users (id),
	client_id TEXT NOT NULL,
	created TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
	expires TIMESTAMP NOT NULL
);

CREATE TABLE refresh_tokens (
	token CHAR(50) NOT NULL PRIMARY KEY,
	user_id UUID REFERENCES users (id),
	client_id TEXT NOT NULL,
	created TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
	expires TIMESTAMP NOT NULL
);

CREATE TABLE access_tokens (
	token CHAR(50) NOT NULL PRIMARY KEY,
	refresh_token CHAR(50) REFERENCES refresh_tokens (token),
	created TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
	expires TIMESTAMP NOT NULL
);

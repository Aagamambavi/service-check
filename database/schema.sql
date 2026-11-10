CREATE TABLE users (
    id BIGSERIAL PRIMARY KEY,
    full_name VARCHAR(100) NOT NULL,
    email VARCHAR(255) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL
);

CREATE TABLE monitored_endpoints (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name VARCHAR(150) NOT NULL,
    url VARCHAR(2048) NOT NULL,
    expected_status INTEGER NOT NULL DEFAULT 200,
    is_active BOOLEAN NOT NULL DEFAULT TRUE
);

CREATE TABLE check_results (
    id BIGSERIAL PRIMARY KEY,
    endpoint_id BIGINT NOT NULL
        REFERENCES monitored_endpoints(id) ON DELETE CASCADE,
    status_code INTEGER,
    response_time_ms INTEGER,
    was_successful BOOLEAN NOT NULL,
    checked_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE incidents (
    id BIGSERIAL PRIMARY KEY,
    endpoint_id BIGINT NOT NULL
        REFERENCES monitored_endpoints(id) ON DELETE CASCADE,
    started_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    recovered_at TIMESTAMPTZ,
    status VARCHAR(20) NOT NULL DEFAULT 'open'
);
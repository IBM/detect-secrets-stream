-- CREATE USER dss_user;
-- CREATE DATABASE dss;
-- GRANT ALL PRIVILEGES ON DATABASE dss TO dss_user;
\c dss;
create table token (
    token_id serial PRIMARY KEY,
    token_cred VARCHAR,
    token_comment VARCHAR,
    token_type VARCHAR NOT NULL,
    first_identified TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    is_live BOOLEAN,
    last_test_date TIMESTAMPTZ,
    last_test_success BOOLEAN,
    token_hash VARCHAR NOT NULL,
    other_factors VARCHAR,
    uuid VARCHAR NOT NULL,
    owner_email VARCHAR,
    remediation_date TIMESTAMPTZ
);
create table token_owner (
    owner_email VARCHAR PRIMARY KEY,
    owner_bu VARCHAR,
    manager_email VARCHAR,
    manager_bu VARCHAR,
    escalation_mgr_email VARCHAR,
    escalation_mgr_bu VARCHAR
);
create table token_commit (
    token_id INTEGER NOT NULL,
    hash VARCHAR NOT NULL,
    repo VARCHAR NOT NULL,
    branch VARCHAR NOT NULL,
    date_scanned TIMESTAMPTZ,
    filename_located VARCHAR NOT NULL,
    linenumber_located VARCHAR NOT NULL,
    author_name VARCHAR,
    author_email VARCHAR,
    pusher_username VARCHAR NOT NULL,
    pusher_email VARCHAR,
    committer_email VARCHAR,
    committer_name VARCHAR,
    location_url VARCHAR NOT NULL,
    commit_id serial PRIMARY KEY,
    repo_public BOOLEAN NOT NULL,
    uniqueness_hash VARCHAR NOT NULL,
    CONSTRAINT unique_leak_hash UNIQUE(uniqueness_hash)
);
create table vmt_report (
    vuln_id VARCHAR,
    token_owner_email VARCHAR,
    token_type VARCHAR,
    vulnerability VARCHAR,
    pusher_email VARCHAR,
    committer_email VARCHAR,
    author_email VARCHAR,
    date_last_tested TIMESTAMPTZ,
    date_remediated TIMESTAMPTZ,
    security_focals VARCHAR,
    repo_public BOOLEAN,
    repo_private BOOLEAN
);
-- user_def = {
--     read_only:
--         (
--             GRANT SELECT ON ALL TABLES IN SCHEMA public TO ,
--             ,
--         ),
--     read_write:
--         (
--             GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA public TO ,
--             GRANT ALL ON ALL SEQUENCES IN SCHEMA public TO ,
--         ),
--     admin:
--         (
--             GRANT ALL ON ALL TABLES IN SCHEMA public TO ,
--             GRANT ALL ON ALL SEQUENCES IN SCHEMA public TO ,
--         ),
-- }

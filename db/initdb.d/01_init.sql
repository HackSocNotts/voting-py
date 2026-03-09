-- Role Creation
DO $$ BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'registration_svc') THEN
        CREATE ROLE registration_svc LOGIN;
    END IF;
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'ballot_svc') THEN
        CREATE ROLE ballot_svc LOGIN;
    END IF;
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'tally_svc') THEN
        CREATE ROLE tally_svc LOGIN;
    END IF;
END $$;

-- Table Creation
CREATE TABLE members (
    id         SERIAL PRIMARY KEY,
    student_id VARCHAR(20) UNIQUE NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE members_voted (
    id         SERIAL PRIMARY KEY,
    student_id VARCHAR(20) UNIQUE NOT NULL REFERENCES members(student_id),
    issued_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE ballots (
    id           SERIAL PRIMARY KEY,
    token        VARCHAR(256) UNIQUE NOT NULL,
    submitted    BOOLEAN NOT NULL DEFAULT FALSE,
    votes        JSONB,
    vote_hmac    VARCHAR(64),   -- HMAC-SHA256(canonical_votes_json, TOKEN_SECRET)
    submitted_at TIMESTAMPTZ
);

CREATE TABLE candidates (
    id         SERIAL PRIMARY KEY,
    role       VARCHAR(255) UNIQUE NOT NULL,
    candidates JSONB NOT NULL,
    idx        INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE election_state (
    id         INTEGER PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    status     VARCHAR(20) NOT NULL DEFAULT 'pending',
    started_at TIMESTAMPTZ,
    results_at TIMESTAMPTZ
);

INSERT INTO election_state (id, status) VALUES (1, 'pending');

-- Grants for registration_svc
GRANT SELECT, INSERT, UPDATE ON members         TO registration_svc;
GRANT SELECT, INSERT         ON members_voted   TO registration_svc;
GRANT SELECT, INSERT         ON ballots         TO registration_svc;
GRANT USAGE, SELECT          ON SEQUENCE members_id_seq        TO registration_svc;
GRANT USAGE, SELECT          ON SEQUENCE members_voted_id_seq  TO registration_svc;
GRANT USAGE, SELECT          ON SEQUENCE ballots_id_seq        TO registration_svc;
GRANT SELECT                 ON election_state  TO registration_svc;

-- Grants for ballot_svc
GRANT SELECT, UPDATE         ON ballots         TO ballot_svc;
GRANT SELECT                 ON candidates      TO ballot_svc;
GRANT SELECT                 ON election_state  TO ballot_svc;

-- Grants for tally_svc
GRANT SELECT, DELETE         ON ballots         TO tally_svc;
GRANT SELECT, DELETE         ON members_voted   TO tally_svc;
GRANT SELECT                 ON members         TO tally_svc;
GRANT SELECT                 ON election_state  TO tally_svc;
GRANT SELECT, INSERT, UPDATE, DELETE ON candidates      TO tally_svc;
GRANT UPDATE                 ON election_state  TO tally_svc;
GRANT USAGE, SELECT          ON SEQUENCE candidates_id_seq     TO tally_svc;
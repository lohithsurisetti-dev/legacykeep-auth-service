-- =============================================================================
-- LegacyKeep Auth Service - Database Initialization
-- =============================================================================

-- Set proper encoding and locale
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;

-- Create extensions if they don't exist
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Create additional databases for different environments
CREATE DATABASE auth_db_dev WITH TEMPLATE template0 ENCODING 'UTF8' LC_COLLATE 'C' LC_CTYPE 'C';
CREATE DATABASE auth_db_test WITH TEMPLATE template0 ENCODING 'UTF8' LC_COLLATE 'C' LC_CTYPE 'C';

-- Grant privileges
GRANT ALL PRIVILEGES ON DATABASE auth_db_dev TO postgres;
GRANT ALL PRIVILEGES ON DATABASE auth_db_test TO postgres;

-- Create a dedicated user for the application (optional)
-- CREATE USER legacykeep_user WITH PASSWORD 'legacykeep_password';
-- GRANT ALL PRIVILEGES ON DATABASE auth_db TO legacykeep_user;
-- GRANT ALL PRIVILEGES ON DATABASE auth_db_dev TO legacykeep_user;
-- GRANT ALL PRIVILEGES ON DATABASE auth_db_test TO legacykeep_user;

-- Set timezone
SET timezone = 'UTC';

-- Log successful initialization
DO $$
BEGIN
    RAISE NOTICE 'LegacyKeep Auth Service database initialization completed successfully!';
    RAISE NOTICE 'Databases created: auth_db, auth_db_dev, auth_db_test';
    RAISE NOTICE 'Extensions installed: uuid-ossp, pgcrypto';
END $$;


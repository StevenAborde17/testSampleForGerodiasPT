-- =====================================================================
-- Streamlined User Schema & Audit Triggers (Developer Alignment)
-- =====================================================================

-- 1. Create Streamlined app_user Table
CREATE TABLE IF NOT EXISTS app_user (
    user_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    username varchar(50) NOT NULL UNIQUE,
    email varchar(100) NOT NULL UNIQUE,
    password_hash text NOT NULL,
    first_name varchar(50) NOT NULL,
    last_name varchar(50) NOT NULL,
    status varchar(20) NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'active', 'rejected')),
    stamp varchar(60)
);

-- 2. Redacted Audit Trigger Function (Protects password_hash in audit_log)
CREATE OR REPLACE FUNCTION trg_audit_log_app_user() RETURNS TRIGGER
LANGUAGE plpgsql AS $$
DECLARE
    v_key TEXT;
    v_old JSONB;
    v_new JSONB;
BEGIN
    v_key := COALESCE(NEW.user_id, OLD.user_id)::text;
    v_old := CASE WHEN OLD IS NOT NULL THEN to_jsonb(OLD) - 'password_hash' ELSE NULL END;
    v_new := CASE WHEN NEW IS NOT NULL THEN to_jsonb(NEW) - 'password_hash' ELSE NULL END;

    IF TG_OP = 'INSERT' THEN
        INSERT INTO audit_log (table_name, action, record_key, old_values, new_values, action_by)
        VALUES (TG_TABLE_NAME, 'ADD', v_key, NULL, v_new, audit_user());
    ELSE
        IF (to_jsonb(OLD) - 'stamp') = (to_jsonb(NEW) - 'stamp') THEN
            RETURN NULL;
        END IF;

        INSERT INTO audit_log (table_name, action, record_key, old_values, new_values, action_by)
        VALUES (TG_TABLE_NAME, 'EDIT', v_key, v_old, v_new, audit_user());
    END IF;

    RETURN NULL;
END;
$$;

-- 3. Attach Triggers to app_user
DROP TRIGGER IF EXISTS app_user_biu_stamp ON app_user;
CREATE TRIGGER app_user_biu_stamp BEFORE INSERT OR UPDATE ON app_user FOR EACH ROW EXECUTE FUNCTION trg_set_stamp();

DROP TRIGGER IF EXISTS app_user_aiu_audit ON app_user;
CREATE TRIGGER app_user_aiu_audit AFTER INSERT OR UPDATE ON app_user FOR EACH ROW EXECUTE FUNCTION trg_audit_log_app_user();

-- 4. Active View for Developer (Filters accounts with 'active' status)
CREATE OR REPLACE VIEW app_user_active WITH (security_invoker = true) AS 
SELECT * FROM app_user WHERE status = 'active';
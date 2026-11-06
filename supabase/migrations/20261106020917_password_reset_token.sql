-- =====================================================================
-- S1-DBA-04: Password Reset Token Table with Redacted Audit Triggers
-- =====================================================================

-- 1. Create Password Reset Token Table
CREATE TABLE IF NOT EXISTS password_reset_token (
    token_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id bigint NOT NULL REFERENCES app_user(user_id),
    token_hash text NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    is_used boolean NOT NULL DEFAULT false,
    is_deleted boolean NOT NULL DEFAULT false,
    stamp varchar(60)
);

-- 2. Redacted Audit Trigger Function (Protects token_hash from exposure in audit_log)
CREATE OR REPLACE FUNCTION trg_audit_log_password_reset_token()
RETURNS trigger AS $$
DECLARE
    v_key text;
    v_old jsonb;
    v_new jsonb;
    v_action text;
BEGIN
    v_key := COALESCE(NEW.token_id, OLD.token_id)::text;
    v_old := CASE WHEN OLD IS NOT NULL THEN to_jsonb(OLD) - 'token_hash' ELSE NULL END;
    v_new := CASE WHEN NEW IS NOT NULL THEN to_jsonb(NEW) - 'token_hash' ELSE NULL END;

    IF TG_OP = 'INSERT' THEN
        INSERT INTO audit_log (table_name, action, record_key, old_values, new_values, action_by)
        VALUES (TG_TABLE_NAME, 'ADD', v_key, NULL, v_new, audit_user());
    ELSE
        IF (to_jsonb(OLD) - 'stamp') = (to_jsonb(NEW) - 'stamp') THEN
            RETURN NULL;
        END IF;

        v_action := CASE 
            WHEN NOT OLD.is_deleted AND NEW.is_deleted THEN 'DELETE'
            WHEN OLD.is_deleted AND NOT NEW.is_deleted THEN 'RESTORE'
            ELSE 'EDIT'
        END;

        INSERT INTO audit_log (table_name, action, record_key, old_values, new_values, action_by)
        VALUES (TG_TABLE_NAME, v_action, v_key, v_old, v_new, audit_user());
    END IF;

    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

-- 3. Attach Safety, Stamp, and Audit Triggers
DROP TRIGGER IF EXISTS password_reset_token_bd_block ON password_reset_token;
CREATE TRIGGER password_reset_token_bd_block BEFORE DELETE ON password_reset_token FOR EACH ROW EXECUTE FUNCTION trg_block_hard_delete();

DROP TRIGGER IF EXISTS password_reset_token_biu_stamp ON password_reset_token;
CREATE TRIGGER password_reset_token_biu_stamp BEFORE INSERT OR UPDATE ON password_reset_token FOR EACH ROW EXECUTE FUNCTION trg_set_stamp();

DROP TRIGGER IF EXISTS password_reset_token_aiu_audit ON password_reset_token;
CREATE TRIGGER password_reset_token_aiu_audit AFTER INSERT OR UPDATE ON password_reset_token FOR EACH ROW EXECUTE FUNCTION trg_audit_log_password_reset_token();

-- 4. Create Security-Invoker Active View
CREATE OR REPLACE VIEW password_reset_token_active WITH (security_invoker = true) AS 
SELECT * FROM password_reset_token WHERE NOT is_deleted;
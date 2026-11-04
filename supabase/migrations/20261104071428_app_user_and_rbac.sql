-- =====================================================================
-- S1-DBA-03: User Management & Role-Based Access Control (RBAC) Schema
-- =====================================================================

-- 1. Create Lookup / Core Tables
CREATE TABLE IF NOT EXISTS role (
    role_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    role_name varchar(30) NOT NULL UNIQUE,
    description text,
    is_deleted boolean NOT NULL DEFAULT false,
    stamp varchar(60)
);

CREATE TABLE IF NOT EXISTS module (
    module_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    module_code varchar(20) NOT NULL UNIQUE,
    module_name varchar(50) NOT NULL,
    description text,
    is_deleted boolean NOT NULL DEFAULT false,
    stamp varchar(60)
);

CREATE TABLE IF NOT EXISTS rights (
    right_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    module_id bigint NOT NULL REFERENCES module(module_id),
    right_code varchar(50) NOT NULL UNIQUE,
    right_name varchar(100) NOT NULL,
    description text,
    is_deleted boolean NOT NULL DEFAULT false,
    stamp varchar(60)
);

-- 2. Create User Table (Includes registration status: pending, active, rejected)
CREATE TABLE IF NOT EXISTS app_user (
    user_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    username varchar(50) NOT NULL UNIQUE,
    email varchar(100) NOT NULL UNIQUE,
    password_hash text NOT NULL,
    first_name varchar(50) NOT NULL,
    last_name varchar(50) NOT NULL,
    role_id bigint REFERENCES role(role_id),
    status varchar(20) NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'active', 'rejected')),
    is_blocked boolean NOT NULL DEFAULT false,
    must_change_password boolean NOT NULL DEFAULT false,
    empno varchar(5) REFERENCES employee(empno),
    is_deleted boolean NOT NULL DEFAULT false,
    stamp varchar(60)
);

CREATE TABLE IF NOT EXISTS user_permission (
    user_id bigint NOT NULL REFERENCES app_user(user_id),
    right_id bigint NOT NULL REFERENCES rights(right_id),
    is_granted boolean NOT NULL DEFAULT true,
    is_deleted boolean NOT NULL DEFAULT false,
    stamp varchar(60),
    PRIMARY KEY (user_id, right_id)
);

-- 3. Redacted Audit Trigger for app_user (Excludes password_hash from audit_log)
CREATE OR REPLACE FUNCTION trg_audit_log_app_user() RETURNS TRIGGER
LANGUAGE plpgsql AS $$
DECLARE
    v_key TEXT;
    v_old JSONB;
    v_new JSONB;
    v_action TEXT;
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
$$;

-- 4. Apply Triggers to Tables
DO $$
DECLARE
    t TEXT;
BEGIN
    FOR t IN SELECT unnest(ARRAY['role', 'module', 'rights', 'user_permission']) LOOP
        EXECUTE format('CREATE TRIGGER %I_bd_block BEFORE DELETE ON %I FOR EACH ROW EXECUTE FUNCTION trg_block_hard_delete()', t, t);
        EXECUTE format('CREATE TRIGGER %I_biu_stamp BEFORE INSERT OR UPDATE ON %I FOR EACH ROW EXECUTE FUNCTION trg_set_stamp()', t, t);
        EXECUTE format('CREATE TRIGGER %I_aiu_audit AFTER INSERT OR UPDATE ON %I FOR EACH ROW EXECUTE FUNCTION trg_audit_log(%L)', t, t, 
                       CASE WHEN t = 'user_permission' THEN 'user_id,right_id' ELSE t || '_id' END);
        EXECUTE format('CREATE OR REPLACE VIEW %I WITH (security_invoker = true) AS SELECT * FROM %I WHERE NOT is_deleted', t || '_active', t);
    END LOOP;
END;
$$;

-- Attach app_user triggers
CREATE TRIGGER app_user_bd_block BEFORE DELETE ON app_user FOR EACH ROW EXECUTE FUNCTION trg_block_hard_delete();
CREATE TRIGGER app_user_biu_stamp BEFORE INSERT OR UPDATE ON app_user FOR EACH ROW EXECUTE FUNCTION trg_set_stamp();
CREATE TRIGGER app_user_aiu_audit AFTER INSERT OR UPDATE ON app_user FOR EACH ROW EXECUTE FUNCTION trg_audit_log_app_user();
CREATE OR REPLACE VIEW app_user_active WITH (security_invoker = true) AS SELECT * FROM app_user WHERE NOT is_deleted;
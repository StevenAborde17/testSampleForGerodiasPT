# Hope, Inc. ERP - Local Setup Guide (No Docker)

## Prerequisites
- Node.js & Git installed
- Supabase CLI installed (`npm install -g supabase`)

## Local Development Setup
1. Clone the repository:
   ```bash
   git clone [https://github.com/StevenAborde17/testSampleForGerodiasPT.git](https://github.com/StevenAborde17/testSampleForGerodiasPT.git)
   cd testSampleForGerodiasPT

   ## 🗄️ Database Architecture & Migration Summary (Sprint 1)

### Baseline & Migration History
1. `DBA-01 / DBA-02`: Baseline Core ERP Schema (`employee`, `department`, `job`, `jobHistory`, `customer`, `sales`, `salesDetail`, `product`, `payment`, `priceHist`), initial sample data, audit logging infrastructure (`audit_log`), stamp triggers, and child protection triggers (`HopeDB_audit.sql`).
2. `DBA-03`: User Management & RBAC Schema (`app_user`, `role`, `module`, `rights`, `user_permission`) supporting `pending`, `active`, and `rejected` account statuses with `password_hash` audit redaction.
3. `DBA-04`: Single-use Password Reset Tokens (`password_reset_token`) with `token_hash` audit redaction.
4. `DBA-05`: Session Logging (`session_log`) for authentication tracking with `session_token` audit redaction.

### Key DB Admin Safeguards for Developers
* **Security Invoker Views:** All active tables have corresponding `_active` views (e.g., `app_user_active`, `customer_active`). Developers should query these views to automatically exclude soft-deleted records (`is_deleted = false`).
* **Soft Delete Enforcement:** Hard `DELETE` operations are blocked by `trg_block_hard_delete()`. Use `UPDATE table SET is_deleted = true` instead.
* **Sensitive Data Redaction:** Audit triggers automatically exclude `password_hash`, `token_hash`, and `session_token` from `audit_log` entries to prevent plaintext credential leaks.
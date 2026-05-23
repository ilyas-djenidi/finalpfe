CyBrain migrations

This folder contains SQL migration scripts for SQLite.

Apply manually (example):
  sqlite3 cybrain.db < migrations/sql/0001_v4_schema.sql

Notes:
- The application also performs safe automatic migrations at startup in database.py.
- Alembic is listed in requirements for future migration workflow standardization.

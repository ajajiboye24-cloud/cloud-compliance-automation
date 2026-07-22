# Design Decisions

## Why SQLite?

SQLite was selected because it is lightweight, requires no server, and is ideal for local development and portfolio projects.

---

## Why two database tables?

The scans table stores metadata about each scan.

The findings table stores the individual compliance findings.

This allows one scan to contain multiple findings.

---

## Why boto3?

boto3 is the official AWS SDK for Python.

It provides authenticated access to AWS services and simplifies interaction with AWS APIs.

---

## Why YAML?

YAML separates compliance knowledge from application logic.

Security framework mappings can be updated without changing Python code.

---

## Why standardize findings?

Every scanner returns the same data structure.

This allows the compliance engine, database, dashboard, and future reporting modules to process findings consistently.
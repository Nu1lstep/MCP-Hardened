"""Seed data/records.db with fake records for the demo. Idempotent."""

import sqlite3
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DB_PATH = ROOT / "data" / "records.db"

RECORDS = [
    ("Acme Landing Page", "public", "Marketing copy for the homepage."),
    ("Pricing Page", "public", "Three tiers: starter, pro, enterprise."),
    ("Blog: Getting Started", "public", "Intro tutorial for new users."),
    ("API Reference", "docs", "Endpoint list and example requests."),
    ("Onboarding Guide", "docs", "Step-by-step setup instructions."),
    ("FAQ", "docs", "Answers to common questions."),
    ("Release Notes v1.2", "docs", "Bug fixes and minor improvements."),
    ("Community Guidelines", "public", "Be kind and stay on topic."),
    ("Ops Credentials", "internal", "INTERNAL_TOKEN=fake-value-do-not-use-seed-data"),
]


def seed() -> None:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("DROP TABLE IF EXISTS records")
    cursor.execute(
        "CREATE TABLE records ("
        "id INTEGER PRIMARY KEY, "
        "name TEXT, "
        "category TEXT, "
        "note TEXT)"
    )
    cursor.executemany(
        "INSERT INTO records (name, category, note) VALUES (?, ?, ?)",
        RECORDS,
    )
    conn.commit()
    conn.close()
    print(f"Seeded {len(RECORDS)} records into {DB_PATH}")


if __name__ == "__main__":
    seed()

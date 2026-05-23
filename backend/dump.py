import sqlite3
db = sqlite3.connect("cybrain.db")
for row in db.execute("SELECT sql FROM sqlite_master WHERE type='table'").fetchall():
    if row[0]: print(row[0])

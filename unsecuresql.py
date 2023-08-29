import sqlite3

conn = sqlite3.connect('src/db.sqlite3')
cursor = conn.cursor()

new_bal = 1000_000
user_id = 2
query_new_bal = f"UPDATE pages_Account SET balance = {new_bal} WHERE user_id = {user_id};"
query_check_bal = f"SELECT balance FROM pages_account WHERE user_id = {user_id};"
with conn:
    old_bal = conn.execute(query_check_bal).fetchone()
    print(f"User_id: {user_id}, has a balance of: {old_bal}")
    conn.execute(query_new_bal)
    conn.commit()
    new_bal = conn.execute(query_check_bal).fetchone()
    print(f"User_id: {user_id}, has a balance of: {new_bal}")

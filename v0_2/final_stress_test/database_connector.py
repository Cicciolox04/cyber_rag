import sqlite3

def get_user_data(user_id):
    # SQL Injection da manuale, ma mascherata da una funzione di log
    query = f"SELECT * FROM users WHERE id = '{user_id}'"
    print(f"DEBUG: Executing query {query}")
    conn = sqlite3.connect('users.db')
    return conn.execute(query).fetchall()
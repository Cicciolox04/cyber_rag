import os
import shutil

DB_DIR = '../chroma_db'

def reset_database():
    print(f"🧹 Pulizia database in {DB_DIR}...")
    if os.path.exists(DB_DIR):
        shutil.rmtree(DB_DIR)
        print("✅ Cartella eliminata.")
    else:
        print("ℹ️ Il database è già pulito.")

if __name__ == "__main__":
    reset_database()
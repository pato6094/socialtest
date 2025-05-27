import sqlite3

def create_tables():
    """Creates the database tables if they don't already exist."""
    conn = None  # Initialize conn to None
    try:
        conn = sqlite3.connect('social_network.db')
        cursor = conn.cursor()

        # Create users table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                email TEXT UNIQUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # Create friendships table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS friendships (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id1 INTEGER NOT NULL,
                user_id2 INTEGER NOT NULL,
                status TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id1) REFERENCES users (id),
                FOREIGN KEY (user_id2) REFERENCES users (id),
                UNIQUE (user_id1, user_id2)
            )
        """)

        # Create groups table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS groups (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL,
                description TEXT,
                creator_id INTEGER NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (creator_id) REFERENCES users (id)
            )
        """)

        # Create posts table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS posts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                content TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                group_id INTEGER,
                FOREIGN KEY (user_id) REFERENCES users (id),
                FOREIGN KEY (group_id) REFERENCES groups (id)
            )
        """)

        # Create messages table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender_id INTEGER NOT NULL,
                receiver_id INTEGER NOT NULL,
                content TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                read_at TIMESTAMP,
                FOREIGN KEY (sender_id) REFERENCES users (id),
                FOREIGN KEY (receiver_id) REFERENCES users (id)
            )
        """)

        # Create group_members table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS group_members (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                group_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                role TEXT NOT NULL DEFAULT 'member',
                joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (group_id) REFERENCES groups (id),
                FOREIGN KEY (user_id) REFERENCES users (id),
                UNIQUE (group_id, user_id)
            )
        """)

        conn.commit()
        print("Tables created successfully.")

    except sqlite3.Error as e:
        print(f"Error creating tables: {e}")

    finally:
        if conn:
            conn.close()

if __name__ == '__main__':
    create_tables()

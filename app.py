import sqlite3
import os
from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash

# Import the function to create tables from database_setup.py
# We'll assume database_setup.py is in the same directory and has a main() or create_tables() function.
try:
    import database_setup
except ImportError:
    # This is a fallback, ideally database_setup.py should be importable.
    # For now, we'll proceed and init_db will try to handle it.
    print("Warning: database_setup.py not found or not importable directly. init_db might fail if tables are not created.")
    database_setup = None


app = Flask(__name__)
app.secret_key = 'supersecretkey' # Should be a strong, random key in production

DATABASE_NAME = 'social_network.db'

def get_db_connection():
    """Connects to the SQLite database and returns a connection object."""
    conn = sqlite3.connect(DATABASE_NAME)
    conn.row_factory = sqlite3.Row # Access columns by name
    return conn

def init_db(app_context=False):
    """Initializes the database by creating tables if they don't exist."""
    db_exists = os.path.exists(DATABASE_NAME)
    
    if not db_exists:
        print(f"{DATABASE_NAME} not found. Attempting to create tables...")
        if database_setup:
            try:
                database_setup.create_tables() # Call the function from database_setup.py
                print("Database tables created successfully by database_setup.py.")
            except Exception as e:
                print(f"Error calling database_setup.create_tables(): {e}")
                # Fallback or further error handling if direct call fails
        else:
            # Fallback: try to establish a connection which might create the file,
            # but tables won't be defined without database_setup.py
            try:
                conn = get_db_connection()
                # Check if users table exists as a proxy for db initialization
                cursor = conn.cursor()
                cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users'")
                if not cursor.fetchone():
                    print("Users table not found. Database might be empty or not initialized correctly.")
                    # Here you could attempt to run SQL from a string if database_setup.py is truly unavailable
                    # For now, we rely on database_setup.py being present and working.
                conn.close()
            except Exception as e:
                print(f"Error during fallback database check: {e}")
    else:
        # Optionally, you could still check if tables exist even if the file exists
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users'")
        if not cursor.fetchone():
            print("Database file exists, but 'users' table not found. Attempting to create tables...")
            if database_setup:
                try:
                    database_setup.create_tables()
                    print("Database tables created successfully by database_setup.py on existing DB file.")
                except Exception as e:
                    print(f"Error calling database_setup.create_tables() on existing DB file: {e}")
            else:
                print("database_setup.py module not available to create tables.")
        conn.close()


@app.cli.command('initdb')
def initdb_command():
    """CLI command to initialize the database."""
    print("Initializing the database...")
    init_db()
    print("Database initialization finished.")

# Automatically initialize DB if it doesn't exist when app starts (for development convenience)
# In a production scenario, you might prefer explicit `flask initdb`.
with app.app_context():
    init_db(app_context=True)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        errors = False

        if not username:
            flash('Username is required.', 'error')
            errors = True
        if not email:
            flash('Email is required.', 'error')
            errors = True
        if not password:
            flash('Password is required.', 'error')
            errors = True
        if not confirm_password:
            flash('Confirm Password is required.', 'error')
            errors = True
        
        if password != confirm_password:
            flash('Passwords do not match.', 'error')
            errors = True

        # Basic email format check (very simple)
        if email and '@' not in email:
            flash('Invalid email format.', 'error')
            errors = True
            
        if errors:
            return render_template('register.html')

        conn = get_db_connection()
        cursor = conn.cursor()

        # Check uniqueness for username
        cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
        if cursor.fetchone():
            flash('Username already exists. Please choose a different one.', 'error')
            errors = True
            
        # Check uniqueness for email
        cursor.execute("SELECT id FROM users WHERE email = ?", (email,))
        if cursor.fetchone():
            flash('Email address already registered. Please use a different one.', 'error')
            errors = True
            
        conn.close() # Close connection after checks

        if errors:
            return render_template('register.html')

        # If all validations pass
        hashed_password = generate_password_hash(password)
        
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
                           (username, email, hashed_password))
            conn.commit()
            flash('Registration successful! Please login.', 'success')
            # The 'login' route is not yet defined, this will cause an error until it is.
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError as e: # Should be caught by earlier checks, but as a safeguard
            flash(f'An error occurred: {e}. Username or email might already be taken.', 'error')
        except sqlite3.Error as e:
            flash(f'A database error occurred: {e}', 'error')
        finally:
            if conn:
                conn.close()
        
        return render_template('register.html')

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if not username or not password:
            flash('Both username and password are required.', 'error')
            return render_template('login.html')

        conn = None
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
            user = cursor.fetchone()

            if user and check_password_hash(user['password_hash'], password):
                session.clear()
                session['user_id'] = user['id']
                session['username'] = user['username']
                flash('Login successful!', 'success')
                return redirect(url_for('main_feed')) # Updated redirect
            else:
                flash('Invalid username or password.', 'danger')
        except sqlite3.Error as e:
            flash(f'A database error occurred: {e}', 'error')
        finally:
            if conn:
                conn.close()
        
        return render_template('login.html')

    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' in session:
        return render_template('dashboard.html', username=session['username'])
    else:
        flash('Please log in to access this page.', 'warning')
        return redirect(url_for('login'))

# Placeholder for logout route, will be implemented later
@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))


@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')

        if not username or not email:
            flash('Both username and email are required.', 'error')
            return render_template('forgot_password.html')

        conn = None
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE username = ? AND email = ?", (username, email))
            user = cursor.fetchone()

            if user:
                session['reset_user_id'] = user['id']
                flash('User verified. Please enter your new password.', 'info')
                return redirect(url_for('reset_password'))
            else:
                flash('Invalid username or email. Please try again.', 'danger')
        except sqlite3.Error as e:
            flash(f'A database error occurred: {e}', 'error')
        finally:
            if conn:
                conn.close()
        
        return render_template('forgot_password.html')

    return render_template('forgot_password.html')


@app.route('/reset-password', methods=['GET', 'POST'])
def reset_password():
    if 'reset_user_id' not in session:
        flash('Password reset request not found or expired. Please try again.', 'warning')
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        new_password = request.form.get('new_password')
        confirm_new_password = request.form.get('confirm_new_password')

        errors = False
        if not new_password:
            flash('New password is required.', 'error')
            errors = True
        if not confirm_new_password:
            flash('Confirm new password is required.', 'error')
            errors = True
        
        if new_password != confirm_new_password:
            flash('Passwords do not match.', 'error')
            errors = True

        if errors:
            return render_template('reset_password.html')

        hashed_password = generate_password_hash(new_password)
        conn = None
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("UPDATE users SET password_hash = ? WHERE id = ?", 
                           (hashed_password, session['reset_user_id']))
            conn.commit()
            session.pop('reset_user_id', None)
            flash('Password has been successfully reset. Please login with your new password.', 'success')
            return redirect(url_for('login'))
        except sqlite3.Error as e:
            flash(f'A database error occurred: {e}', 'error')
        finally:
            if conn:
                conn.close()
        
        return render_template('reset_password.html') # Should ideally not be reached if successful

    return render_template('reset_password.html')


@app.route('/profile')
def profile():
    if 'user_id' not in session:
        flash('Please log in to view your profile.', 'warning')
        return redirect(url_for('login'))

    user_id = session['user_id']
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id, username, email, created_at FROM users WHERE id = ?", (user_id,))
        user_data = cursor.fetchone()

        if user_data:
            return render_template('profile.html', user=user_data)
        else:
            # This case should ideally not be reached if session user_id is valid
            # and the user exists in the database.
            flash('Could not retrieve user profile. User not found. Please try logging in again.', 'danger')
            session.clear() # Clear session as a precaution
            return redirect(url_for('login'))

    except sqlite3.Error as e:
        flash(f'A database error occurred: {e}', 'error')
        return redirect(url_for('dashboard')) # Or some other error page
    finally:
        if conn:
            conn.close()

# Helper function to get user by ID
def get_user_by_id(user_id):
    conn = get_db_connection()
    user = conn.execute("SELECT id, username, email FROM users WHERE id = ?", (user_id,)).fetchone()
    conn.close()
    return user

# Helper function to get friendship status
def get_friendship_status(user1_id, user2_id):
    conn = get_db_connection()
    # Check for existing friendship in either direction
    friendship = conn.execute("""
        SELECT * FROM friendships
        WHERE (user_id1 = ? AND user_id2 = ?) OR (user_id1 = ? AND user_id2 = ?)
    """, (user1_id, user2_id, user2_id, user1_id)).fetchone()
    conn.close()

    if friendship:
        if friendship['status'] == 'accepted':
            return "Friends"
        elif friendship['status'] == 'pending':
            if friendship['user_id1'] == user1_id: # User1 sent the request to User2
                return "Request Sent"
            else: # User1 received the request from User2
                return "Request Received"
    return "Not Friends"


@app.route('/users')
def users_list():
    if 'user_id' not in session:
        flash('Please log in to view users.', 'warning')
        return redirect(url_for('login'))

    current_user_id = session['user_id']
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        # Fetch all users except the current user
        cursor.execute("SELECT id, username FROM users WHERE id != ?", (current_user_id,))
        all_users = cursor.fetchall()
        
        users_with_status = []
        for user in all_users:
            status = get_friendship_status(current_user_id, user['id'])
            users_with_status.append({'id': user['id'], 'username': user['username'], 'status': status})
            
        return render_template('users_list.html', users=users_with_status)

    except sqlite3.Error as e:
        flash(f'A database error occurred: {e}', 'error')
        return redirect(url_for('dashboard'))
    finally:
        if conn:
            conn.close()


@app.route('/send_friend_request/<int:recipient_user_id>', methods=['POST'])
def send_friend_request(recipient_user_id):
    if 'user_id' not in session:
        flash('Please log in to send friend requests.', 'warning')
        return redirect(url_for('login'))

    sender_id = session['user_id']

    if sender_id == recipient_user_id:
        flash('You cannot send a friend request to yourself.', 'error')
        return redirect(url_for('users_list'))

    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Check if a friendship record already exists
        status = get_friendship_status(sender_id, recipient_user_id)
        if status != "Not Friends":
            flash(f'Cannot send request: Status is already "{status}".', 'info')
            return redirect(url_for('users_list'))

        cursor.execute("INSERT INTO friendships (user_id1, user_id2, status) VALUES (?, ?, 'pending')",
                       (sender_id, recipient_user_id))
        conn.commit()
        flash('Friend request sent successfully.', 'success')

    except sqlite3.IntegrityError: # Handles potential unique constraint violation if somehow missed
        flash('Friend request already sent or you are already friends.', 'warning')
    except sqlite3.Error as e:
        flash(f'A database error occurred: {e}', 'error')
    finally:
        if conn:
            conn.close()
    
    return redirect(url_for('users_list'))


@app.route('/friend_requests')
def friend_requests():
    if 'user_id' not in session:
        flash('Please log in to view friend requests.', 'warning')
        return redirect(url_for('login'))

    user_id2 = session['user_id']
    conn = None
    try:
        conn = get_db_connection()
        # Fetch pending requests where the current user is user_id2
        # and join with users table to get the sender's username
        requests = conn.execute("""
            SELECT f.id as request_id, u.username as sender_username, f.created_at 
            FROM friendships f
            JOIN users u ON f.user_id1 = u.id
            WHERE f.user_id2 = ? AND f.status = 'pending'
            ORDER BY f.created_at DESC
        """, (user_id2,)).fetchall()
        
        return render_template('friend_requests.html', requests=requests)

    except sqlite3.Error as e:
        flash(f'A database error occurred: {e}', 'error')
        return redirect(url_for('dashboard'))
    finally:
        if conn:
            conn.close()


@app.route('/accept_friend_request/<int:request_id>', methods=['POST'])
def accept_friend_request(request_id):
    if 'user_id' not in session:
        flash('Please log in to manage friend requests.', 'warning')
        return redirect(url_for('login'))

    current_user_id = session['user_id']
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Fetch the request to verify
        request_data = cursor.execute("SELECT * FROM friendships WHERE id = ?", (request_id,)).fetchone()

        if not request_data:
            flash('Friend request not found.', 'error')
            return redirect(url_for('friend_requests'))

        if request_data['user_id2'] != current_user_id or request_data['status'] != 'pending':
            flash('Invalid request or you do not have permission to accept this request.', 'error')
            return redirect(url_for('friend_requests'))

        cursor.execute("UPDATE friendships SET status = 'accepted' WHERE id = ?", (request_id,))
        conn.commit()
        flash('Friend request accepted!', 'success')

    except sqlite3.Error as e:
        flash(f'A database error occurred: {e}', 'error')
    finally:
        if conn:
            conn.close()
            
    return redirect(url_for('friend_requests'))


@app.route('/decline_friend_request/<int:request_id>', methods=['POST'])
def decline_friend_request(request_id):
    if 'user_id' not in session:
        flash('Please log in to manage friend requests.', 'warning')
        return redirect(url_for('login'))

    current_user_id = session['user_id']
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        request_data = cursor.execute("SELECT * FROM friendships WHERE id = ?", (request_id,)).fetchone()

        if not request_data:
            flash('Friend request not found.', 'error')
            return redirect(url_for('friend_requests'))

        if request_data['user_id2'] != current_user_id or request_data['status'] != 'pending':
            flash('Invalid request or you do not have permission to decline this request.', 'error')
            return redirect(url_for('friend_requests'))

        # Option 1: Delete the request
        cursor.execute("DELETE FROM friendships WHERE id = ?", (request_id,))
        # Option 2: Set status to 'declined' (if you want to keep a record)
        # cursor.execute("UPDATE friendships SET status = 'declined' WHERE id = ?", (request_id,))
        conn.commit()
        flash('Friend request declined.', 'info')

    except sqlite3.Error as e:
        flash(f'A database error occurred: {e}', 'error')
    finally:
        if conn:
            conn.close()
            
    return redirect(url_for('friend_requests'))


@app.route('/friends')
def friends_list():
    if 'user_id' not in session:
        flash('Please log in to view your friends.', 'warning')
        return redirect(url_for('login'))

    current_user_id = session['user_id']
    conn = None
    try:
        conn = get_db_connection()
        # Fetch accepted friendships where the current user is either user_id1 or user_id2
        # and join with users table to get friend's username
        friends_data = conn.execute("""
            SELECT 
                f.id as friendship_id, 
                CASE 
                    WHEN f.user_id1 = ? THEN u2.id 
                    ELSE u1.id 
                END as friend_user_id,
                CASE 
                    WHEN f.user_id1 = ? THEN u2.username 
                    ELSE u1.username 
                END as friend_username
            FROM friendships f
            JOIN users u1 ON f.user_id1 = u1.id
            JOIN users u2 ON f.user_id2 = u2.id
            WHERE (f.user_id1 = ? OR f.user_id2 = ?) AND f.status = 'accepted'
        """, (current_user_id, current_user_id, current_user_id, current_user_id)).fetchall()
        
        return render_template('friends_list.html', friends=friends_data)

    except sqlite3.Error as e:
        flash(f'A database error occurred: {e}', 'error')
        return redirect(url_for('dashboard'))
    finally:
        if conn:
            conn.close()


@app.route('/remove_friend/<int:friend_user_id>', methods=['POST'])
def remove_friend(friend_user_id):
    if 'user_id' not in session:
        flash('Please log in to manage your friends.', 'warning')
        return redirect(url_for('login'))

    current_user_id = session['user_id']
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Delete the friendship record regardless of who is user_id1 or user_id2
        result = cursor.execute("""
            DELETE FROM friendships 
            WHERE status = 'accepted' AND 
                  ((user_id1 = ? AND user_id2 = ?) OR (user_id1 = ? AND user_id2 = ?))
        """, (current_user_id, friend_user_id, friend_user_id, current_user_id))
        conn.commit()

        if result.rowcount > 0:
            flash('Friend removed successfully.', 'success')
        else:
            flash('Friendship not found or already removed.', 'info')

    except sqlite3.Error as e:
        flash(f'A database error occurred: {e}', 'error')
    finally:
        if conn:
            conn.close()
            
    return redirect(url_for('friends_list'))


@app.route('/create_post', methods=['GET', 'POST'])
def create_post():
    if 'user_id' not in session:
        flash('Please log in to create a post.', 'warning')
        return redirect(url_for('login'))

    if request.method == 'POST':
        content = request.form.get('content')

        if not content or not content.strip():
            flash('Post content cannot be empty.', 'danger')
            return render_template('create_post.html')

        user_id = session['user_id']
        conn = None
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("INSERT INTO posts (user_id, content) VALUES (?, ?)",
                           (user_id, content))
            conn.commit()
            flash('Post created successfully!', 'success')
            return redirect(url_for('my_posts'))
        except sqlite3.Error as e:
            flash(f'A database error occurred: {e}', 'error')
        finally:
            if conn:
                conn.close()
        
        return render_template('create_post.html') # In case of error, re-render with form

    return render_template('create_post.html')


@app.route('/my_posts')
def my_posts():
    if 'user_id' not in session:
        flash('Please log in to view your posts.', 'warning')
        return redirect(url_for('login'))

    user_id = session['user_id']
    conn = None
    try:
        conn = get_db_connection()
        # SQLite stores TIMESTAMP as text by default, so they should be directly usable
        # or convertable by Python's datetime if needed.
        # No special parsing needed for strftime if they are stored in a compatible format.
        # The schema defines created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        posts = conn.execute("SELECT id, content, created_at FROM posts WHERE user_id = ? ORDER BY created_at DESC",
                             (user_id,)).fetchall()
        return render_template('my_posts.html', posts=posts)
    except sqlite3.Error as e:
        flash(f'A database error occurred while fetching posts: {e}', 'error')
        return render_template('my_posts.html', posts=[]) # Pass empty list on error
    finally:
        if conn:
            conn.close()


@app.route('/')
def main_feed():
    if 'user_id' not in session:
        flash('Please log in to view the feed.', 'warning')
        return redirect(url_for('login'))

    current_user_id = session['user_id']
    conn = None
    posts_for_feed = []

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Fetch friend IDs
        cursor.execute("""
            SELECT user_id2 FROM friendships WHERE user_id1 = ? AND status = 'accepted'
            UNION
            SELECT user_id1 FROM friendships WHERE user_id2 = ? AND status = 'accepted'
        """, (current_user_id, current_user_id))
        
        friend_ids_tuples = cursor.fetchall()
        friend_ids = [row['user_id2'] for row in friend_ids_tuples] # Assuming 'user_id2' is the alias from UNION

        # Construct list of user IDs for the feed (current user + friends)
        feed_user_ids = list(set([current_user_id] + friend_ids))
        
        if not feed_user_ids: # Should not happen if user is logged in, but as a safeguard
            return render_template('feed.html', posts=[])

        # Create a string of placeholders for the IN clause
        placeholders = ','.join('?' for _ in feed_user_ids)
        
        # Fetch posts from these users, joining with users table for username
        query = f"""
            SELECT p.id, p.content, p.created_at, u.username as author_username
            FROM posts p
            JOIN users u ON p.user_id = u.id
            WHERE p.user_id IN ({placeholders})
            ORDER BY p.created_at DESC
        """
        
        cursor.execute(query, feed_user_ids)
        posts_for_feed = cursor.fetchall()

    except sqlite3.Error as e:
        flash(f'A database error occurred while fetching the feed: {e}', 'error')
    finally:
        if conn:
            conn.close()
            
    return render_template('feed.html', posts=posts_for_feed)


@app.route('/chat/<int:friend_user_id>')
def chat_page(friend_user_id):
    if 'user_id' not in session:
        flash('Please log in to chat.', 'warning')
        return redirect(url_for('login'))

    current_user_id = session['user_id']

    # Verify Friendship
    friendship = get_friendship_status(current_user_id, friend_user_id)
    if friendship != "Friends":
        flash('You can only chat with friends.', 'danger')
        return redirect(url_for('friends_list'))

    conn = None
    friend_username = None
    messages_list = []
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Fetch friend's username
        friend_user = cursor.execute("SELECT username FROM users WHERE id = ?", (friend_user_id,)).fetchone()
        if not friend_user:
            flash('Friend not found.', 'error')
            return redirect(url_for('friends_list'))
        friend_username = friend_user['username']

        # Fetch Messages
        # For each message, it's useful to know if the current_user_id is the sender to style it in the template.
        # The sender_id column already provides this information.
        cursor.execute("""
            SELECT id, sender_id, receiver_id, content, created_at
            FROM messages
            WHERE (sender_id = ? AND receiver_id = ?) OR (sender_id = ? AND receiver_id = ?)
            ORDER BY created_at ASC
        """, (current_user_id, friend_user_id, friend_user_id, current_user_id))
        messages_list = cursor.fetchall()
        
        # Mark messages as read (if applicable - simple version for now, no read_at update)
        # This is where you might update `read_at` for messages received by current_user_id from friend_user_id

    except sqlite3.Error as e:
        flash(f'A database error occurred: {e}', 'error')
        return redirect(url_for('friends_list')) # Or dashboard
    finally:
        if conn:
            conn.close()

    return render_template('chat.html', friend_user_id=friend_user_id, friend_username=friend_username, messages_list=messages_list)


@app.route('/send_message/<int:receiver_user_id>', methods=['POST'])
def send_message_to_user(receiver_user_id):
    if 'user_id' not in session:
        flash('Please log in to send messages.', 'warning')
        return redirect(url_for('login'))

    sender_id = session['user_id']
    content = request.form.get('content')

    if not content or not content.strip():
        flash('Message content cannot be empty.', 'danger')
        return redirect(url_for('chat_page', friend_user_id=receiver_user_id))

    # Verify Friendship
    friendship = get_friendship_status(sender_id, receiver_user_id)
    if friendship != "Friends":
        flash('You can only send messages to friends.', 'danger')
        # Decide a more appropriate redirect, maybe back to friends_list or user_list
        return redirect(url_for('friends_list')) 

    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("INSERT INTO messages (sender_id, receiver_id, content) VALUES (?, ?, ?)",
                       (sender_id, receiver_user_id, content))
        conn.commit()
        # flash('Message sent!', 'success') # Optional, can be noisy
    except sqlite3.Error as e:
        flash(f'A database error occurred: {e}', 'error')
    finally:
        if conn:
            conn.close()
    
    return redirect(url_for('chat_page', friend_user_id=receiver_user_id))


if __name__ == '__main__':
    # Ensure Werkzeug is available
    try:
        from werkzeug.security import generate_password_hash
        print("Werkzeug is available.")
    except ImportError:
        print("Werkzeug is NOT available. Please install it: pip install Werkzeug")
    
    # Note: app.run() is for development. For production, use a WSGI server like Gunicorn.
    app.run(debug=True)

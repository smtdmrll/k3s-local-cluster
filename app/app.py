import os
import redis
import psycopg2
from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'dev-secret-key')

POSTGRES_HOST = os.environ.get('POSTGRES_HOST', 'localhost')
POSTGRES_PORT = os.environ.get('POSTGRES_PORT', '5432')
POSTGRES_DB = os.environ.get('POSTGRES_DB', 'appdb')
POSTGRES_USER = os.environ.get('POSTGRES_USER', 'appuser')
POSTGRES_PASSWORD = os.environ.get('POSTGRES_PASSWORD', '')

REDIS_HOST = os.environ.get('REDIS_HOST', 'localhost')
REDIS_PORT = int(os.environ.get('REDIS_PORT', '6379'))
REDIS_PASSWORD = os.environ.get('REDIS_PASSWORD', '')

def get_db_connection():
    return psycopg2.connect(
        host=POSTGRES_HOST,
        port=POSTGRES_PORT,
        database=POSTGRES_DB,
        user=POSTGRES_USER,
        password=POSTGRES_PASSWORD
    )

def get_redis_connection():
    return redis.Redis(
        host=REDIS_HOST,
        port=REDIS_PORT,
        password=REDIS_PASSWORD,
        decode_responses=True
    )

def init_db():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            username VARCHAR(80) UNIQUE NOT NULL,
            email VARCHAR(120) UNIQUE NOT NULL,
            password_hash VARCHAR(255) NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    cur.execute('''
        CREATE TABLE IF NOT EXISTS login_history (
            id SERIAL PRIMARY KEY,
            user_id INTEGER REFERENCES users(id),
            login_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            ip_address VARCHAR(45)
        )
    ''')
    conn.commit()
    cur.close()
    conn.close()

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def get_cached_user(user_id):
    r = get_redis_connection()
    cache_key = f"user:{user_id}"
    cached = r.get(cache_key)
    if cached:
        return eval(cached)
    
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('SELECT id, username, email FROM users WHERE id = %s', (user_id,))
    user = cur.fetchone()
    cur.close()
    conn.close()
    
    if user:
        user_data = {'id': user[0], 'username': user[1], 'email': user[2]}
        r.setex(cache_key, 300, str(user_data))
        return user_data
    return None

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/health')
def health():
    return {'status': 'alive'}, 200

@app.route('/ready')
def ready():
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute('SELECT 1')
        cur.close()
        conn.close()
        
        r = get_redis_connection()
        r.ping()
        
        return {'status': 'ready', 'database': 'connected', 'cache': 'connected'}, 200
    except Exception as e:
        return {'status': 'not_ready', 'error': str(e)}, 503

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute('SELECT id, username, password_hash FROM users WHERE username = %s', (username,))
        user = cur.fetchone()
        
        if user and check_password_hash(user[2], password):
            session['user_id'] = user[0]
            session['username'] = user[1]
            
            cur.execute(
                'INSERT INTO login_history (user_id, ip_address) VALUES (%s, %s)',
                (user[0], request.remote_addr)
            )
            conn.commit()
            
            r = get_redis_connection()
            r.incr(f"login_count:{user[0]}")
            
            cur.close()
            conn.close()
            return redirect(url_for('dashboard'))
        
        cur.close()
        conn.close()
        flash('Invalid username or password')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        
        conn = get_db_connection()
        cur = conn.cursor()
        
        try:
            cur.execute(
                'INSERT INTO users (username, email, password_hash) VALUES (%s, %s, %s)',
                (username, email, generate_password_hash(password))
            )
            conn.commit()
            flash('Registration successful. Please login.')
            return redirect(url_for('login'))
        except psycopg2.IntegrityError:
            conn.rollback()
            flash('Username or email already exists')
        finally:
            cur.close()
            conn.close()
    
    return render_template('register.html')

@app.route('/dashboard')
@login_required
def dashboard():
    user = get_cached_user(session['user_id'])
    
    r = get_redis_connection()
    login_count = r.get(f"login_count:{session['user_id']}") or 0
    
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(
        'SELECT login_time, ip_address FROM login_history WHERE user_id = %s ORDER BY login_time DESC LIMIT 5',
        (session['user_id'],)
    )
    login_history = cur.fetchall()
    cur.close()
    conn.close()
    
    return render_template('dashboard.html', user=user, login_count=login_count, login_history=login_history)

@app.route('/logout')
def logout():
    if 'user_id' in session:
        r = get_redis_connection()
        r.delete(f"user:{session['user_id']}")
    session.clear()
    return redirect(url_for('login'))

with app.app_context():
    try:
        init_db()
    except Exception:
        pass

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)

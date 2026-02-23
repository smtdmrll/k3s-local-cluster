import os
import io
import re
import redis
import psycopg2
import paramiko
import threading
import json
import time
from flask import Flask, render_template, request, redirect, url_for, session, flash, Response, stream_with_context, jsonify
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
        host=POSTGRES_HOST, port=POSTGRES_PORT,
        database=POSTGRES_DB, user=POSTGRES_USER, password=POSTGRES_PASSWORD
    )


def get_redis_connection():
    return redis.Redis(host=REDIS_HOST, port=REDIS_PORT, password=REDIS_PASSWORD, decode_responses=True)


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
    cur.execute('''
        CREATE TABLE IF NOT EXISTS deployments (
            id SERIAL PRIMARY KEY,
            user_id INTEGER REFERENCES users(id),
            server_ip VARCHAR(45) NOT NULL,
            docker_image VARCHAR(255) NOT NULL,
            action VARCHAR(20) NOT NULL,
            status VARCHAR(20) DEFAULT 'pending',
            log TEXT DEFAULT '',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            finished_at TIMESTAMP
        )
    ''')
    cur.execute('''
        CREATE TABLE IF NOT EXISTS established_apps (
            id SERIAL PRIMARY KEY,
            user_id INTEGER REFERENCES users(id),
            app_name VARCHAR(100) NOT NULL,
            image VARCHAR(255) NOT NULL,
            namespace VARCHAR(100) NOT NULL,
            container_port INTEGER DEFAULT 80,
            node_port INTEGER,
            server_ip VARCHAR(45) DEFAULT '',
            status VARCHAR(20) DEFAULT 'pending',
            url VARCHAR(255),
            log TEXT DEFAULT '',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    cur.execute('''
        CREATE TABLE IF NOT EXISTS saved_servers (
            id SERIAL PRIMARY KEY,
            user_id INTEGER REFERENCES users(id),
            name VARCHAR(100) NOT NULL,
            server_ip VARCHAR(45) NOT NULL,
            ssh_key TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(user_id, name)
        )
    ''')
    # Migrate: add new columns to established_apps if they don't exist
    for col, coldef in [
        ('server_ip', "VARCHAR(45) DEFAULT ''"),
        ('log', "TEXT DEFAULT ''"),
    ]:
        try:
            cur.execute(f"ALTER TABLE established_apps ADD COLUMN {col} {coldef}")
        except Exception:
            conn.rollback()
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


# ─────────────────────────────────────────────
#  Auth & Pages
# ─────────────────────────────────────────────

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
            cur.execute('INSERT INTO login_history (user_id, ip_address) VALUES (%s, %s)',
                        (user[0], request.remote_addr))
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
            cur.execute('INSERT INTO users (username, email, password_hash) VALUES (%s, %s, %s)',
                        (username, email, generate_password_hash(password)))
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
    cur.execute('SELECT login_time, ip_address FROM login_history WHERE user_id = %s ORDER BY login_time DESC LIMIT 5',
                (session['user_id'],))
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


# ─────────────────────────────────────────────
#  Saved Servers API
# ─────────────────────────────────────────────

@app.route('/api/servers', methods=['GET'])
@login_required
def api_list_servers():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('SELECT id, name, server_ip, created_at FROM saved_servers WHERE user_id = %s ORDER BY name',
                (session['user_id'],))
    rows = cur.fetchall()
    cur.close()
    conn.close()
    return jsonify([{'id': r[0], 'name': r[1], 'server_ip': r[2]} for r in rows])

@app.route('/api/servers', methods=['POST'])
@login_required
def api_save_server():
    data = request.get_json()
    name = data.get('name', '').strip()
    server_ip = data.get('server_ip', '').strip()
    ssh_key = data.get('ssh_key', '').strip()
    if not name or not server_ip or not ssh_key:
        return jsonify({'error': 'name, server_ip, ssh_key required'}), 400
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute(
            'INSERT INTO saved_servers (user_id, name, server_ip, ssh_key) VALUES (%s, %s, %s, %s) '
            'ON CONFLICT (user_id, name) DO UPDATE SET server_ip = EXCLUDED.server_ip, ssh_key = EXCLUDED.ssh_key '
            'RETURNING id',
            (session['user_id'], name, server_ip, ssh_key)
        )
        sid = cur.fetchone()[0]
        conn.commit()
    except Exception as e:
        conn.rollback()
        cur.close()
        conn.close()
        return jsonify({'error': str(e)}), 500
    cur.close()
    conn.close()
    return jsonify({'id': sid, 'name': name, 'server_ip': server_ip})

@app.route('/api/servers/<int:server_id>', methods=['GET'])
@login_required
def api_get_server(server_id):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('SELECT id, name, server_ip, ssh_key FROM saved_servers WHERE id = %s AND user_id = %s',
                (server_id, session['user_id']))
    row = cur.fetchone()
    cur.close()
    conn.close()
    if not row:
        return jsonify({'error': 'not found'}), 404
    return jsonify({'id': row[0], 'name': row[1], 'server_ip': row[2], 'ssh_key': row[3]})

@app.route('/api/servers/<int:server_id>', methods=['DELETE'])
@login_required
def api_delete_server(server_id):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('DELETE FROM saved_servers WHERE id = %s AND user_id = %s', (server_id, session['user_id']))
    conn.commit()
    cur.close()
    conn.close()
    return jsonify({'ok': True})


# ─────────────────────────────────────────────
#  SSH Helpers
# ─────────────────────────────────────────────

def _parse_ssh_key(ssh_key_content):
    key_file = io.StringIO(ssh_key_content)
    try:
        return paramiko.RSAKey.from_private_key(key_file)
    except Exception:
        key_file.seek(0)
        try:
            return paramiko.Ed25519Key.from_private_key(key_file)
        except Exception:
            key_file.seek(0)
            return paramiko.ECDSAKey.from_private_key(key_file)

def _ssh_connect(server_ip, pkey):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(server_ip, username='devops', pkey=pkey, timeout=30)
    return ssh


# ─────────────────────────────────────────────
#  Deploy Manager
# ─────────────────────────────────────────────

def _update_deployment(deploy_id, **fields):
    conn = get_db_connection()
    cur = conn.cursor()
    sets = ', '.join(f"{k} = %s" for k in fields)
    cur.execute(f"UPDATE deployments SET {sets} WHERE id = %s", list(fields.values()) + [deploy_id])
    conn.commit()
    cur.close()
    conn.close()

def _append_log(deploy_id, line):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("UPDATE deployments SET log = log || %s WHERE id = %s", (line + '\n', deploy_id))
    conn.commit()
    cur.close()
    conn.close()

def _run_ssh_command(ssh, command, deploy_id):
    _append_log(deploy_id, f"$ {command}")
    stdin, stdout, stderr = ssh.exec_command(command, timeout=600)
    output = ''
    for line in stdout:
        text = line.strip()
        output += text + '\n'
        _append_log(deploy_id, text)
    err = stderr.read().decode().strip()
    if err:
        _append_log(deploy_id, f"STDERR: {err}")
        output += err + '\n'
    exit_code = stdout.channel.recv_exit_status()
    return exit_code, output


def _deploy_worker(deploy_id, server_ip, ssh_key_content, action, deploy_app, app_image, app_helm, user_id):
    try:
        _update_deployment(deploy_id, status='running')
        _append_log(deploy_id, f"Connecting to {server_ip}...")

        pkey = _parse_ssh_key(ssh_key_content)
        ssh = _ssh_connect(server_ip, pkey)
        _append_log(deploy_id, f"Connected to {server_ip} as devops")

        if action == 'install':
            # Step 1: Clone repo
            _append_log(deploy_id, "=" * 50)
            _append_log(deploy_id, "STEP 1: Cloning project repository...")
            _append_log(deploy_id, "=" * 50)
            _run_ssh_command(ssh,
                'if [ ! -d /home/devops/k3s-local-cluster ]; then '
                'git clone https://github.com/smtdmrll/k3s-local-cluster.git /home/devops/k3s-local-cluster; '
                'else cd /home/devops/k3s-local-cluster && git pull; fi',
                deploy_id)

            # Step 2: Run k3s-project.sh install
            _append_log(deploy_id, "=" * 50)
            _append_log(deploy_id, "STEP 2: Installing K3s cluster + components...")
            _append_log(deploy_id, "=" * 50)
            code, _ = _run_ssh_command(ssh,
                'sudo bash /home/devops/k3s-local-cluster/scripts/k3s-project.sh install',
                deploy_id)
            if code != 0:
                _update_deployment(deploy_id, status='failed', finished_at=time.strftime('%Y-%m-%d %H:%M:%S'))
                _append_log(deploy_id, "ERROR: Cluster installation failed!")
                ssh.close()
                return

            # Step 3: Deploy app if requested
            if deploy_app and (app_image or app_helm):
                _append_log(deploy_id, "=" * 50)
                _append_log(deploy_id, "STEP 3: Deploying application...")
                _append_log(deploy_id, "=" * 50)

                if app_helm:
                    parts = app_helm.split('/')
                    if len(parts) == 2:
                        repo_name, chart_name = parts
                        release_name = re.sub(r'[^a-z0-9\-]', '-', chart_name.lower()).strip('-')[:50]
                        cmds = [
                            f'sudo helm repo add {repo_name} https://charts.{repo_name}.com/{repo_name} 2>/dev/null || true',
                            'sudo helm repo update',
                            'sudo kubectl create namespace apps --dry-run=client -o yaml | sudo kubectl apply -f -',
                            f'sudo helm upgrade --install {release_name} {app_helm} --namespace apps --wait --timeout=300s',
                            'sudo kubectl get pods -n apps',
                            'sudo kubectl get svc -n apps',
                        ]
                    else:
                        release_name = re.sub(r'[^a-z0-9\-]', '-', app_helm.lower()).strip('-')[:50]
                        cmds = [
                            'sudo kubectl create namespace apps --dry-run=client -o yaml | sudo kubectl apply -f -',
                            f'sudo helm upgrade --install {release_name} {app_helm} --namespace apps --wait --timeout=300s',
                            'sudo kubectl get pods -n apps',
                            'sudo kubectl get svc -n apps',
                        ]
                    for cmd in cmds:
                        _run_ssh_command(ssh, cmd, deploy_id)

                elif app_image:
                    img_name = app_image.split(':')[0].split('/')[-1]
                    deploy_name = re.sub(r'[^a-z0-9\-]', '-', img_name.lower()).strip('-')[:50] or 'app'
                    cmds = [
                        'sudo kubectl create namespace apps --dry-run=client -o yaml | sudo kubectl apply -f -',
                        f'sudo kubectl create deployment {deploy_name} --image={app_image} -n apps --dry-run=client -o yaml | sudo kubectl apply -f -',
                        f'sudo kubectl rollout status deployment/{deploy_name} -n apps --timeout=180s',
                        f'sudo kubectl expose deployment {deploy_name} --type=NodePort --port=80 -n apps --dry-run=client -o yaml | sudo kubectl apply -f -',
                        'sudo kubectl get pods -n apps',
                        'sudo kubectl get svc -n apps',
                    ]
                    for cmd in cmds:
                        _run_ssh_command(ssh, cmd, deploy_id)

                _append_log(deploy_id, "Application deployment completed!")

            _append_log(deploy_id, "=" * 50)
            _append_log(deploy_id, "K3s cluster is ready! ✅")
            _append_log(deploy_id, "=" * 50)
            _update_deployment(deploy_id, status='success', finished_at=time.strftime('%Y-%m-%d %H:%M:%S'))

        elif action == 'delete':
            _append_log(deploy_id, "=" * 50)
            _append_log(deploy_id, "Deleting K3s cluster...")
            _append_log(deploy_id, "=" * 50)
            code, _ = _run_ssh_command(ssh,
                'if [ -f /home/devops/k3s-local-cluster/scripts/k3s-project.sh ]; then '
                'sudo bash /home/devops/k3s-local-cluster/scripts/k3s-project.sh delete; '
                'elif [ -f /usr/local/bin/k3s-uninstall.sh ]; then '
                'sudo /usr/local/bin/k3s-uninstall.sh; '
                'else echo "No uninstall method found"; exit 1; fi',
                deploy_id)
            status = 'success' if code == 0 else 'failed'
            _append_log(deploy_id, f"Cluster deletion: {status}")
            _update_deployment(deploy_id, status=status, finished_at=time.strftime('%Y-%m-%d %H:%M:%S'))

        ssh.close()
    except Exception as e:
        _append_log(deploy_id, f"FATAL ERROR: {str(e)}")
        _update_deployment(deploy_id, status='failed', finished_at=time.strftime('%Y-%m-%d %H:%M:%S'))


@app.route('/deploy', methods=['GET', 'POST'])
@login_required
def deploy():
    if request.method == 'POST':
        server_ip = request.form.get('server_ip', '').strip()
        ssh_key_text = request.form.get('ssh_key', '').strip()
        action = request.form.get('action', 'install')
        deploy_app = request.form.get('deploy_app') == 'yes'
        app_image = request.form.get('app_image', '').strip()
        app_helm = request.form.get('app_helm', '').strip()

        errors = []
        if not server_ip:
            errors.append('Server IP is required')
        if not ssh_key_text:
            errors.append('SSH Private Key is required')
        if action not in ('install', 'delete'):
            errors.append('Invalid action')
        if errors:
            for e in errors:
                flash(e)
            return redirect(url_for('deploy'))

        desc = 'K3s Cluster'
        if deploy_app and app_image:
            desc = f'K3s + Image: {app_image}'
        elif deploy_app and app_helm:
            desc = f'K3s + Helm: {app_helm}'

        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute(
            'INSERT INTO deployments (user_id, server_ip, docker_image, action, status) VALUES (%s, %s, %s, %s, %s) RETURNING id',
            (session['user_id'], server_ip, desc, action, 'pending')
        )
        deploy_id = cur.fetchone()[0]
        conn.commit()
        cur.close()
        conn.close()

        thread = threading.Thread(
            target=_deploy_worker,
            args=(deploy_id, server_ip, ssh_key_text, action, deploy_app, app_image, app_helm, session['user_id']),
            daemon=True
        )
        thread.start()
        flash(f'Deployment #{deploy_id} started! Action: {action}')
        return redirect(url_for('deploy_status', deploy_id=deploy_id))

    # GET
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(
        'SELECT id, server_ip, docker_image, action, status, created_at, finished_at '
        'FROM deployments WHERE user_id = %s ORDER BY id DESC LIMIT 20',
        (session['user_id'],)
    )
    history = cur.fetchall()
    cur.close()
    conn.close()
    return render_template('deploy.html', history=history)


@app.route('/deploy/<int:deploy_id>')
@login_required
def deploy_status(deploy_id):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(
        'SELECT id, server_ip, docker_image, action, status, log, created_at, finished_at '
        'FROM deployments WHERE id = %s AND user_id = %s',
        (deploy_id, session['user_id'])
    )
    deployment = cur.fetchone()
    cur.close()
    conn.close()
    if not deployment:
        flash('Deployment not found')
        return redirect(url_for('deploy'))
    return render_template('deploy_status.html', d=deployment)


@app.route('/api/deploy/<int:deploy_id>/status')
@login_required
def api_deploy_status(deploy_id):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('SELECT status, log FROM deployments WHERE id = %s AND user_id = %s',
                (deploy_id, session['user_id']))
    row = cur.fetchone()
    cur.close()
    conn.close()
    if not row:
        return {'error': 'not found'}, 404
    return {'status': row[0], 'log': row[1]}


# ─────────────────────────────────────────────
#  Image Establisher (SSH-based remote cluster)
# ─────────────────────────────────────────────

def _sanitize_name(image):
    name = image.split('/')[-1].split(':')[0]
    name = re.sub(r'[^a-z0-9\-]', '-', name.lower())
    name = re.sub(r'-+', '-', name).strip('-')
    return name[:50] or 'app'

def _update_established(app_id, **fields):
    conn = get_db_connection()
    cur = conn.cursor()
    sets = ', '.join(f"{k} = %s" for k in fields)
    cur.execute(f"UPDATE established_apps SET {sets} WHERE id = %s", list(fields.values()) + [app_id])
    conn.commit()
    cur.close()
    conn.close()

def _append_est_log(app_id, line):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("UPDATE established_apps SET log = COALESCE(log, '') || %s WHERE id = %s", (line + '\n', app_id))
    conn.commit()
    cur.close()
    conn.close()

def _run_ssh_cmd_est(ssh, command, app_id):
    _append_est_log(app_id, f"$ {command}")
    stdin, stdout, stderr = ssh.exec_command(command, timeout=300)
    output = ''
    for line in stdout:
        text = line.strip()
        output += text + '\n'
        _append_est_log(app_id, text)
    err = stderr.read().decode().strip()
    if err:
        _append_est_log(app_id, f"STDERR: {err}")
        output += err + '\n'
    exit_code = stdout.channel.recv_exit_status()
    return exit_code, output


def _establish_worker(app_id, image, container_port, server_ip, ssh_key_content):
    namespace = f"est-{app_id}"
    app_name = f"est-app-{app_id}"
    try:
        _update_established(app_id, status='creating', namespace=namespace, server_ip=server_ip)
        _append_est_log(app_id, f"Connecting to {server_ip}...")

        pkey = _parse_ssh_key(ssh_key_content)
        ssh = _ssh_connect(server_ip, pkey)
        _append_est_log(app_id, f"Connected to {server_ip}")

        # 1. Create namespace
        _append_est_log(app_id, f"Creating namespace: {namespace}")
        _run_ssh_cmd_est(ssh,
            f'sudo kubectl create namespace {namespace} --dry-run=client -o yaml | sudo kubectl apply -f -',
            app_id)

        # 2. Create deployment
        _append_est_log(app_id, f"Deploying: {image}")
        _run_ssh_cmd_est(ssh,
            f'sudo kubectl create deployment {app_name} --image={image} -n {namespace} --dry-run=client -o yaml | sudo kubectl apply -f -',
            app_id)

        # 3. Wait for rollout
        _append_est_log(app_id, "Waiting for rollout...")
        _run_ssh_cmd_est(ssh,
            f'sudo kubectl rollout status deployment/{app_name} -n {namespace} --timeout=180s',
            app_id)

        # 4. Expose as NodePort
        _append_est_log(app_id, f"Exposing on port {container_port}...")
        _run_ssh_cmd_est(ssh,
            f'sudo kubectl expose deployment {app_name} --type=NodePort --port={container_port} '
            f'-n {namespace} --dry-run=client -o yaml | sudo kubectl apply -f -',
            app_id)

        # 5. Get NodePort
        code, out = _run_ssh_cmd_est(ssh,
            f"sudo kubectl get svc {app_name} -n {namespace} -o jsonpath='{{.spec.ports[0].nodePort}}'",
            app_id)
        node_port = int(out.strip()) if out.strip().isdigit() else 0

        # 6. Get node IP
        code, out = _run_ssh_cmd_est(ssh,
            "sudo kubectl get nodes -o jsonpath='{.items[0].status.addresses[?(@.type==\"InternalIP\")].address}'",
            app_id)
        node_ip = out.strip() or server_ip

        url = f"http://{node_ip}:{node_port}" if node_port else f"http://{server_ip}:?"
        _append_est_log(app_id, f"App available at: {url}")
        _run_ssh_cmd_est(ssh, f'sudo kubectl get pods -n {namespace}', app_id)

        _update_established(app_id, status='running', node_port=node_port, url=url)
        ssh.close()
    except Exception as e:
        _append_est_log(app_id, f"ERROR: {str(e)}")
        _update_established(app_id, status='failed', url=str(e)[:250])


def _destroy_established(app_id, ssh_key_content=None):
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute('SELECT namespace, server_ip FROM established_apps WHERE id = %s', (app_id,))
        row = cur.fetchone()
        cur.close()
        conn.close()
        if not row or not row[0] or not row[1]:
            _update_established(app_id, status='deleted')
            return

        namespace, server_ip = row[0], row[1]

        # Try provided key first, then look up saved key
        if not ssh_key_content:
            conn = get_db_connection()
            cur = conn.cursor()
            cur.execute('SELECT ssh_key FROM saved_servers WHERE server_ip = %s ORDER BY id DESC LIMIT 1', (server_ip,))
            key_row = cur.fetchone()
            cur.close()
            conn.close()
            if not key_row:
                _update_established(app_id, status='failed', url='No saved SSH key for this server')
                return
            ssh_key_content = key_row[0]

        pkey = _parse_ssh_key(ssh_key_content)
        ssh = _ssh_connect(server_ip, pkey)
        _run_ssh_cmd_est(ssh, f'sudo kubectl delete namespace {namespace} --ignore-not-found', app_id)
        ssh.close()
        _update_established(app_id, status='deleted')
    except Exception as e:
        _update_established(app_id, status='failed', url=f"Delete error: {str(e)[:200]}")


@app.route('/establish', methods=['GET', 'POST'])
@login_required
def establish():
    if request.method == 'POST':
        image = request.form.get('image', '').strip()
        port_str = request.form.get('port', '80').strip()
        server_ip = request.form.get('server_ip', '').strip()
        ssh_key_text = request.form.get('ssh_key', '').strip()
        container_port = int(port_str) if port_str.isdigit() else 80

        errors = []
        if not image:
            errors.append('Docker image name is required')
        if not server_ip:
            errors.append('Server IP is required')
        if not ssh_key_text:
            errors.append('SSH Private Key is required')
        if errors:
            for e in errors:
                flash(e)
            return redirect(url_for('establish'))

        app_name = _sanitize_name(image)
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute(
            'INSERT INTO established_apps (user_id, app_name, image, namespace, container_port, server_ip, status) '
            'VALUES (%s, %s, %s, %s, %s, %s, %s) RETURNING id',
            (session['user_id'], app_name, image, '', container_port, server_ip, 'pending')
        )
        est_id = cur.fetchone()[0]
        conn.commit()
        cur.close()
        conn.close()

        thread = threading.Thread(
            target=_establish_worker,
            args=(est_id, image, container_port, server_ip, ssh_key_text),
            daemon=True
        )
        thread.start()
        flash(f'Image #{est_id} is being established on {server_ip}...')
        return redirect(url_for('establish'))

    # GET
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(
        'SELECT id, app_name, image, namespace, node_port, status, url, created_at, server_ip '
        'FROM established_apps WHERE user_id = %s ORDER BY id DESC LIMIT 30',
        (session['user_id'],)
    )
    apps = cur.fetchall()
    cur.close()
    conn.close()
    return render_template('establish.html', apps=apps)


@app.route('/establish/<int:est_id>/delete', methods=['POST'])
@login_required
def establish_delete(est_id):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('SELECT id FROM established_apps WHERE id = %s AND user_id = %s', (est_id, session['user_id']))
    if not cur.fetchone():
        flash('App not found')
    else:
        thread = threading.Thread(target=_destroy_established, args=(est_id,), daemon=True)
        thread.start()
        flash(f'App #{est_id} is being deleted...')
    cur.close()
    conn.close()
    return redirect(url_for('establish'))


@app.route('/api/establish/<int:est_id>/status')
@login_required
def api_establish_status(est_id):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('SELECT status, url, node_port FROM established_apps WHERE id = %s AND user_id = %s',
                (est_id, session['user_id']))
    row = cur.fetchone()
    cur.close()
    conn.close()
    if not row:
        return jsonify({'error': 'not found'}), 404
    return jsonify({'status': row[0], 'url': row[1], 'node_port': row[2]})


with app.app_context():
    try:
        init_db()
    except Exception:
        pass

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)

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
from kubernetes import client as k8s_client, config as k8s_config

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
    cur.execute('''
        CREATE TABLE IF NOT EXISTS deployments (
            id SERIAL PRIMARY KEY,
            user_id INTEGER REFERENCES users(id),
            server_ip VARCHAR(45) NOT NULL,
            docker_image VARCHAR(255) NOT NULL,
            action VARCHAR(10) NOT NULL,
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
            status VARCHAR(20) DEFAULT 'pending',
            url VARCHAR(255),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
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


# ─────────────────────────────────────────────
#  Deployment Manager
# ─────────────────────────────────────────────

def _update_deployment(deploy_id, **fields):
    """Update deployment record in DB."""
    conn = get_db_connection()
    cur = conn.cursor()
    sets = ', '.join(f"{k} = %s" for k in fields)
    cur.execute(f"UPDATE deployments SET {sets} WHERE id = %s",
                list(fields.values()) + [deploy_id])
    conn.commit()
    cur.close()
    conn.close()


def _append_log(deploy_id, line):
    """Append a line to the deployment log."""
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("UPDATE deployments SET log = log || %s WHERE id = %s",
                (line + '\n', deploy_id))
    conn.commit()
    cur.close()
    conn.close()


def _run_ssh_command(ssh, command, deploy_id):
    """Execute a command over SSH and stream output to DB log."""
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


def _deploy_worker(deploy_id, server_ip, ssh_key_content, docker_image, action, user_id):
    """Background thread: SSH into server and run install/delete."""
    try:
        _update_deployment(deploy_id, status='running')
        _append_log(deploy_id, f"Connecting to {server_ip}...")

        # Parse SSH key
        key_file = io.StringIO(ssh_key_content)
        try:
            pkey = paramiko.RSAKey.from_private_key(key_file)
        except Exception:
            key_file.seek(0)
            try:
                pkey = paramiko.Ed25519Key.from_private_key(key_file)
            except Exception:
                key_file.seek(0)
                pkey = paramiko.ECDSAKey.from_private_key(key_file)

        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(server_ip, username='devops', pkey=pkey, timeout=30)
        _append_log(deploy_id, f"Connected to {server_ip} as devops")

        if action == 'install':
            # Step 1: Clone repo & install cluster
            _append_log(deploy_id, "="*50)
            _append_log(deploy_id, "STEP 1: Setting up K3s cluster...")
            _append_log(deploy_id, "="*50)

            code, _ = _run_ssh_command(ssh,
                'if [ ! -d /home/devops/k3s-local-cluster ]; then '
                'git clone https://github.com/smtdmrll/k3s-local-cluster.git /home/devops/k3s-local-cluster; '
                'fi', deploy_id)

            code, _ = _run_ssh_command(ssh,
                'sudo bash /home/devops/k3s-local-cluster/scripts/k3s-project.sh install',
                deploy_id)

            if code != 0:
                _update_deployment(deploy_id, status='failed',
                                   finished_at=time.strftime('%Y-%m-%d %H:%M:%S'))
                _append_log(deploy_id, "ERROR: Cluster installation failed!")
                ssh.close()
                return

            # Step 2: Deploy custom image
            _append_log(deploy_id, "="*50)
            _append_log(deploy_id, f"STEP 2: Deploying custom image: {docker_image}")
            _append_log(deploy_id, "="*50)

            image_name = docker_image.split(':')[0].split('/')[-1]
            deploy_name = image_name.replace('.', '-').replace('_', '-')

            commands = [
                f'sudo kubectl create namespace custom-apps --dry-run=client -o yaml | sudo kubectl apply -f -',
                f'sudo kubectl create deployment {deploy_name} --image={docker_image} -n custom-apps --dry-run=client -o yaml | sudo kubectl apply -f -',
                f'sudo kubectl set image deployment/{deploy_name} {deploy_name}={docker_image} -n custom-apps 2>/dev/null || true',
                f'sudo kubectl rollout status deployment/{deploy_name} -n custom-apps --timeout=180s',
                f'sudo kubectl get pods -n custom-apps',
            ]

            for cmd in commands:
                code, _ = _run_ssh_command(ssh, cmd, deploy_id)

            _append_log(deploy_id, "="*50)
            _append_log(deploy_id, "Deployment completed successfully!")
            _append_log(deploy_id, "="*50)
            _update_deployment(deploy_id, status='success',
                               finished_at=time.strftime('%Y-%m-%d %H:%M:%S'))

        elif action == 'delete':
            _append_log(deploy_id, "="*50)
            _append_log(deploy_id, "Deleting cluster...")
            _append_log(deploy_id, "="*50)

            code, _ = _run_ssh_command(ssh,
                'sudo bash /home/devops/k3s-local-cluster/scripts/k3s-project.sh delete',
                deploy_id)

            status = 'success' if code == 0 else 'failed'
            _append_log(deploy_id, f"Cluster deletion: {status}")
            _update_deployment(deploy_id, status=status,
                               finished_at=time.strftime('%Y-%m-%d %H:%M:%S'))

        ssh.close()

    except Exception as e:
        _append_log(deploy_id, f"FATAL ERROR: {str(e)}")
        _update_deployment(deploy_id, status='failed',
                           finished_at=time.strftime('%Y-%m-%d %H:%M:%S'))


@app.route('/deploy', methods=['GET', 'POST'])
@login_required
def deploy():
    if request.method == 'POST':
        server_ip = request.form.get('server_ip', '').strip()
        docker_image = request.form.get('docker_image', '').strip()
        ssh_key_text = request.form.get('ssh_key', '').strip()
        action = request.form.get('action', 'install')

        # Validate
        errors = []
        if not server_ip:
            errors.append('Server IP is required')
        if not docker_image and action == 'install':
            errors.append('Docker Image is required for install')
        if not ssh_key_text:
            errors.append('SSH Private Key is required')
        if action not in ('install', 'delete'):
            errors.append('Invalid action')

        if errors:
            for e in errors:
                flash(e)
            return redirect(url_for('deploy'))

        # Create deployment record
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute(
            'INSERT INTO deployments (user_id, server_ip, docker_image, action, status) '
            'VALUES (%s, %s, %s, %s, %s) RETURNING id',
            (session['user_id'], server_ip, docker_image or 'N/A', action, 'pending')
        )
        deploy_id = cur.fetchone()[0]
        conn.commit()
        cur.close()
        conn.close()

        # Start background thread
        thread = threading.Thread(
            target=_deploy_worker,
            args=(deploy_id, server_ip, ssh_key_text, docker_image, action, session['user_id']),
            daemon=True
        )
        thread.start()

        flash(f'Deployment #{deploy_id} started! Action: {action}')
        return redirect(url_for('deploy_status', deploy_id=deploy_id))

    # GET — show form + history
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
    cur.execute(
        'SELECT status, log FROM deployments WHERE id = %s AND user_id = %s',
        (deploy_id, session['user_id'])
    )
    row = cur.fetchone()
    cur.close()
    conn.close()

    if not row:
        return {'error': 'not found'}, 404

    return {'status': row[0], 'log': row[1]}

# ─────────────────────────────────────────────
#  Image Establisher
# ─────────────────────────────────────────────

def _get_k8s_clients():
    """Get Kubernetes API clients (in-cluster or local kubeconfig)."""
    try:
        k8s_config.load_incluster_config()
    except Exception:
        k8s_config.load_kube_config()
    return k8s_client.CoreV1Api(), k8s_client.AppsV1Api()


def _get_node_ip():
    """Get the first node's InternalIP."""
    v1, _ = _get_k8s_clients()
    nodes = v1.list_node()
    for addr in nodes.items[0].status.addresses:
        if addr.type == 'InternalIP':
            return addr.address
    return nodes.items[0].status.addresses[0].address


def _sanitize_name(image):
    """Convert a Docker image name to a valid K8s resource name."""
    name = image.split('/')[-1].split(':')[0]
    name = re.sub(r'[^a-z0-9\-]', '-', name.lower())
    name = re.sub(r'-+', '-', name).strip('-')
    return name[:50] or 'app'


def _update_established(app_id, **fields):
    """Update an established_apps record."""
    conn = get_db_connection()
    cur = conn.cursor()
    sets = ', '.join(f"{k} = %s" for k in fields)
    cur.execute(f"UPDATE established_apps SET {sets} WHERE id = %s",
                list(fields.values()) + [app_id])
    conn.commit()
    cur.close()
    conn.close()


def _establish_worker(app_id, image, container_port):
    """Background thread: create namespace + deployment + NodePort service."""
    namespace = f"est-{app_id}"
    app_name = f"est-app-{app_id}"
    try:
        _update_established(app_id, status='creating', namespace=namespace)
        v1, apps_v1 = _get_k8s_clients()

        # 1. Create namespace
        v1.create_namespace(
            k8s_client.V1Namespace(metadata=k8s_client.V1ObjectMeta(name=namespace))
        )

        # 2. Create deployment
        deployment = k8s_client.V1Deployment(
            metadata=k8s_client.V1ObjectMeta(name=app_name, namespace=namespace),
            spec=k8s_client.V1DeploymentSpec(
                replicas=1,
                selector=k8s_client.V1LabelSelector(match_labels={'app': app_name}),
                template=k8s_client.V1PodTemplateSpec(
                    metadata=k8s_client.V1ObjectMeta(labels={'app': app_name}),
                    spec=k8s_client.V1PodSpec(containers=[
                        k8s_client.V1Container(
                            name=app_name,
                            image=image,
                            ports=[k8s_client.V1ContainerPort(container_port=container_port)]
                        )
                    ])
                )
            )
        )
        apps_v1.create_namespaced_deployment(namespace, deployment)

        # 3. Create NodePort service
        service = k8s_client.V1Service(
            metadata=k8s_client.V1ObjectMeta(name=app_name, namespace=namespace),
            spec=k8s_client.V1ServiceSpec(
                type='NodePort',
                selector={'app': app_name},
                ports=[k8s_client.V1ServicePort(port=container_port, target_port=container_port)]
            )
        )
        svc = v1.create_namespaced_service(namespace, service)
        node_port = svc.spec.ports[0].node_port

        # 4. Wait for rollout (max 120s)
        for _ in range(24):
            dep = apps_v1.read_namespaced_deployment_status(app_name, namespace)
            if dep.status.ready_replicas and dep.status.ready_replicas >= 1:
                break
            time.sleep(5)

        # 5. Build URL
        node_ip = _get_node_ip()
        url = f"http://{node_ip}:{node_port}"

        _update_established(app_id, status='running', node_port=node_port, url=url)

    except Exception as e:
        _update_established(app_id, status='failed', url=str(e)[:250])


def _destroy_established(app_id):
    """Delete namespace (cascades all resources)."""
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute('SELECT namespace FROM established_apps WHERE id = %s', (app_id,))
        row = cur.fetchone()
        cur.close()
        conn.close()
        if not row or not row[0]:
            return

        v1, _ = _get_k8s_clients()
        v1.delete_namespace(row[0])
        _update_established(app_id, status='deleted')
    except Exception as e:
        _update_established(app_id, status='failed', url=f"Delete error: {str(e)[:200]}")


@app.route('/establish', methods=['GET', 'POST'])
@login_required
def establish():
    if request.method == 'POST':
        image = request.form.get('image', '').strip()
        port_str = request.form.get('port', '80').strip()
        container_port = int(port_str) if port_str.isdigit() else 80

        if not image:
            flash('Docker image name is required')
            return redirect(url_for('establish'))

        app_name = _sanitize_name(image)

        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute(
            'INSERT INTO established_apps (user_id, app_name, image, namespace, container_port, status) '
            'VALUES (%s, %s, %s, %s, %s, %s) RETURNING id',
            (session['user_id'], app_name, image, '', container_port, 'pending')
        )
        est_id = cur.fetchone()[0]
        conn.commit()
        cur.close()
        conn.close()

        thread = threading.Thread(
            target=_establish_worker,
            args=(est_id, image, container_port),
            daemon=True
        )
        thread.start()

        flash(f'Image #{est_id} is being established...')
        return redirect(url_for('establish'))

    # GET — list
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(
        'SELECT id, app_name, image, namespace, node_port, status, url, created_at '
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
    cur.execute(
        'SELECT status, url, node_port FROM established_apps WHERE id = %s AND user_id = %s',
        (est_id, session['user_id'])
    )
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

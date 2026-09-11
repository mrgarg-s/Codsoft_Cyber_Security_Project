from __future__ import annotations
import os, secrets, sqlite3, time, io
from pathlib import Path
from flask import Flask, abort, flash, redirect, render_template_string, request, send_file, session, url_for
from cryptography.fernet import Fernet, InvalidToken
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

BASE=Path(__file__).resolve().parent
DATA=BASE/'data'; DATA.mkdir(exist_ok=True)
DB=BASE/'app.db'; KEY_FILE=BASE/'secret.key'
app=Flask(__name__)
app.config.update(SECRET_KEY=os.environ.get('FLASK_SECRET_KEY', secrets.token_hex(32)), MAX_CONTENT_LENGTH=16*1024*1024)

def get_key():
    if KEY_FILE.exists(): return KEY_FILE.read_bytes()
    key=Fernet.generate_key(); KEY_FILE.write_bytes(key); return key
fernet=Fernet(get_key())

def db():
    c=sqlite3.connect(DB); c.row_factory=sqlite3.Row; return c

def init_db():
    with db() as c:
        c.executescript("""CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN ('user','admin')));CREATE TABLE IF NOT EXISTS files(id INTEGER PRIMARY KEY, owner_id INTEGER NOT NULL, original_name TEXT NOT NULL, stored_name TEXT NOT NULL, created_at INTEGER NOT NULL, FOREIGN KEY(owner_id) REFERENCES users(id));CREATE TABLE IF NOT EXISTS links(token TEXT PRIMARY KEY, file_id INTEGER NOT NULL, expires_at INTEGER NOT NULL, FOREIGN KEY(file_id) REFERENCES files(id));""")
        if not c.execute('SELECT 1 FROM users WHERE username=?',('admin',)).fetchone():
            c.execute('INSERT INTO users(username,password_hash,role) VALUES(?,?,?)',('admin',generate_password_hash(os.environ.get('ADMIN_PASSWORD','ChangeMe-Admin-123!')),'admin'))

def current_user():
    uid=session.get('uid')
    if not uid:return None
    with db() as c:return c.execute('SELECT * FROM users WHERE id=?',(uid,)).fetchone()

def require_login():
    if not current_user(): abort(401)

def can_access(user,file_row): return user and (user['role']=='admin' or file_row['owner_id']==user['id'])

PAGE="""<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>SecureShare</title><style>body{font-family:system-ui;background:#f5f7fb;margin:0;color:#172033}main{max-width:900px;margin:auto;padding:30px}.box{background:#fff;padding:22px;border-radius:14px;margin:18px 0;box-shadow:0 5px 20px #0001}input,button{padding:10px;margin:5px 0}button{background:#1458b8;color:#fff;border:0;border-radius:8px;font-weight:700}a{color:#1458b8}.flash{padding:10px;background:#fff5d6;border-left:4px solid #c28a00}.file{display:flex;justify-content:space-between;gap:10px;border-bottom:1px solid #eee;padding:10px 0}</style></head><body><main><h1>SecureShare</h1>{% for m in get_flashed_messages() %}<div class="flash">{{m}}</div>{% endfor %}<!--CONTENT--></main></body></html>"""
LOGIN="""<div class="box"><h2>Login</h2><form method="post"><input name="username" placeholder="Username" required maxlength="80"><br><input name="password" type="password" placeholder="Password" required><br><button>Login</button></form><p>Don't have an account? <a href="{{url_for('register')}}">Register here</a>.</p><p>Demo admin is created on first run. Set <code>ADMIN_PASSWORD</code> before production use.</p></div>"""
REGISTER="""<div class="box"><h2>Register</h2><form method="post"><input name="username" placeholder="Username" required maxlength="80"><br><input name="password" type="password" placeholder="Password" required><br><button>Register</button></form><p><a href="{{url_for('login')}}">Back to Login</a></p></div>"""
HOME="""<p>Signed in as <b>{{user['username']}}</b> ({{user['role']}}) &middot; <a href="{{url_for('logout')}}">Logout</a></p><div class="box"><h2>Upload encrypted file</h2><form method="post" action="{{url_for('upload')}}" enctype="multipart/form-data"><input type="file" name="file" required><button>Upload</button></form></div><div class="box"><h2>Your accessible files</h2>{% for f in files %}<div class="file"><span>{{f['original_name']}}<small> &middot; {{f['created_at']}}</small></span><span><a href="{{url_for('download',file_id=f['id'])}}">Download</a> &middot; <a href="{{url_for('link',file_id=f['id'])}}">Temporary link</a></span></div>{% else %}<p>No files yet.</p>{% endfor %}</div>"""
LINK="""<div class="box"><h2>Temporary download link</h2><p>Expires in {{minutes}} minute(s).</p><input style="width:100%" value="{{url}}" readonly><p>Share this link only with the intended recipient.</p><a href="{{url_for('home')}}">Back</a></div>"""

@app.errorhandler(401)
def unauthorized(e):
    return redirect(url_for('login'))

@app.route('/',methods=['GET'])
def home():
    require_login(); u=current_user()
    with db() as c:
        fs=c.execute('SELECT * FROM files WHERE owner_id=? ORDER BY created_at DESC',(u['id'],)).fetchall() if u['role']=='user' else c.execute('SELECT * FROM files ORDER BY created_at DESC').fetchall()
    return render_template_string(PAGE.replace('<!--CONTENT-->', HOME), user=u, files=fs)

@app.route('/login',methods=['GET','POST'])
def login():
    if request.method=='POST':
        username=request.form.get('username','').strip()[:80]; password=request.form.get('password','')
        with db() as c:u=c.execute('SELECT * FROM users WHERE username=?',(username,)).fetchone()
        if u and check_password_hash(u['password_hash'],password): session.clear();session['uid']=u['id'];return redirect(url_for('home'))
        flash('Invalid username or password.')
    return render_template_string(PAGE.replace('<!--CONTENT-->', LOGIN))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()[:80]
        password = request.form.get('password', '')
        if not username or not password:
            flash('Username and password are required.')
            return redirect(url_for('register'))
        with db() as c:
            if c.execute('SELECT 1 FROM users WHERE username=?', (username,)).fetchone():
                flash('Username already exists.')
                return redirect(url_for('register'))
            c.execute('INSERT INTO users(username, password_hash, role) VALUES(?, ?, ?)', (username, generate_password_hash(password), 'user'))
        flash('Registration successful. Please log in.')
        return redirect(url_for('login'))
    return render_template_string(PAGE.replace('<!--CONTENT-->', REGISTER))

@app.get('/logout')
def logout(): session.clear();return redirect(url_for('login'))

@app.post('/upload')
def upload():
    require_login(); f=request.files.get('file')
    if not f or not f.filename: flash('Choose a file.');return redirect(url_for('home'))
    name=secure_filename(f.filename) or 'download.bin'
    data=f.read()
    if len(data)>app.config['MAX_CONTENT_LENGTH']: abort(413)
    token_name=secrets.token_hex(24)+'.enc'; (DATA/token_name).write_bytes(fernet.encrypt(data))
    u=current_user()
    with db() as c:c.execute('INSERT INTO files(owner_id,original_name,stored_name,created_at) VALUES(?,?,?,?)',(u['id'],name,token_name,int(time.time())))
    flash('File encrypted and uploaded successfully.');return redirect(url_for('home'))

@app.get('/download/<int:file_id>')
def download(file_id):
    require_login();u=current_user()
    with db() as c:f=c.execute('SELECT * FROM files WHERE id=?',(file_id,)).fetchone()
    if not f or not can_access(u,f):abort(403)
    path=DATA/f['stored_name']
    if not path.exists():abort(404)
    try:plain=fernet.decrypt(path.read_bytes())
    except InvalidToken:abort(500)
    return send_file(io.BytesIO(plain), as_attachment=True, download_name=f['original_name'], max_age=0)

@app.get('/link/<int:file_id>')
def link(file_id):
    require_login();u=current_user()
    with db() as c:f=c.execute('SELECT * FROM files WHERE id=?',(file_id,)).fetchone()
    if not f or not can_access(u,f):abort(403)
    token=secrets.token_urlsafe(32);expires=int(time.time())+600
    with db() as c:c.execute('INSERT INTO links(token,file_id,expires_at) VALUES(?,?,?)',(token,file_id,expires))
    return render_template_string(PAGE.replace('<!--CONTENT-->', LINK), url=url_for('temporary_download',token=token,_external=True),minutes=10)

@app.get('/s/<token>')
def temporary_download(token):
    with db() as c:
        row=c.execute('SELECT l.*,f.* FROM links l JOIN files f ON f.id=l.file_id WHERE l.token=?',(token,)).fetchone()
    if not row or row['expires_at']<int(time.time()):abort(404)
    path=DATA/row['stored_name']
    if not path.exists():abort(404)
    try:plain=fernet.decrypt(path.read_bytes())
    except InvalidToken:abort(500)
    return send_file(io.BytesIO(plain), as_attachment=True, download_name=row['original_name'], max_age=0)

@app.cli.command('cleanup-links')
def cleanup_links():
    with db() as c:r=c.execute('DELETE FROM links WHERE expires_at<?',(int(time.time()),));print(f'Deleted {r.rowcount} expired links.')

init_db()
if __name__=='__main__': app.run(debug=False)

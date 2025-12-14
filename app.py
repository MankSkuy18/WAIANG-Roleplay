from flask import Flask, render_template, redirect, url_for, request, flash, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from authlib.integrations.flask_client import OAuth
import os
import urllib.parse
from datetime import datetime

app = Flask(__name__)

# Konfigurasi Database (MongoDB)
app.config['SECRET_KEY'] = 'kunci_yang_sangat_private'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///roleplay.db'  # Database SQLite lokal
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Konfigurasi Flask-Login
login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

# Konfigurasi OAuth (harus setelah app config)
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'  # Hanya untuk pengembangan lokal (HTTP)
oauth = OAuth(app)

# --- MODEL DATABASE ---
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    name = db.Column(db.String(150))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- ROUTES WEBSITE ---

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        # 1. Cari apakah user ada di database
        user = User.query.filter_by(username=username).first()

        if user:
            # Jika User DITEMUKAN, langkah selanjutnya cek password
            if check_password_hash(user.password, password):
                # KONDISI 1: User ada DAN Password benar (SUKSES)
                login_user(user)
                return redirect(url_for('index'))
            else:
                # KONDISI 2: User ada TAPI Password salah
                flash('Login gagal. Periksa username dan password!')
        else:
            # KONDISI 3: User TIDAK DITEMUKAN di database (Kosong)
            flash('Login gagal. Akun belum terdaftar. Silakan daftarkan akun anda!')
            
    return render_template('login.html')

google = oauth.register(
    name='google',
    client_id='415750162126-nrf5igj42d765r7luki7pc23s3kmu6o2.apps.googleusercontent.com',
    client_secret='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',
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={'scope': 'email profile'}
)

@app.route('/login/google')
def login_google():
    # Mengarahkan user ke halaman login Google
    redirect_uri = url_for('google_auth', _external=True)
    return google.authorize_redirect(redirect_uri)

@app.route('/auth/google')
def google_auth():
    # Google mengembalikan user ke sini setelah login sukses
    token = google.authorize_access_token()
    user_info = google.get('https://www.googleapis.com/oauth2/v1/userinfo').json()
    
    # Ambil data dari Google
    google_email = user_info['email']
    google_name = user_info['name']
    
    # Cek apakah user sudah ada di database kita berdasarkan email/username
    user = User.query.filter_by(username=google_email).first()

    if not user:
        # Jika belum ada, buat user baru otomatis
        # Password kita buat acak karena mereka login pakai Google
        import secrets
        random_password = secrets.token_hex(16) 
        
        new_user = User(
            username=google_email, 
            name=google_name, 
            password=generate_password_hash(random_password)
        )
        db.session.add(new_user)
        db.session.commit()
        user = new_user

    # Login user tersebut
    login_user(user)
    return redirect(url_for('index'))

# Di bawah konfigurasi Google yang sudah ada

facebook = oauth.register(
    name='facebook',
    client_id='1910712902858792',
    client_secret='21fa4b7662a45e77ec2ca791e9d54905',
    access_token_url='https://graph.facebook.com/oauth/access_token',
    access_token_params=None,
    authorize_url='https://www.facebook.com/dialog/oauth',
    authorize_params=None,
    api_base_url='https://graph.facebook.com/',
    client_kwargs={'scope': 'email public_profile'},
)

# --- ROUTE FACEBOOK ---
@app.route('/login/facebook')
def login_facebook():
    redirect_uri = url_for('facebook_auth', _external=True)
    return facebook.authorize_redirect(redirect_uri)

@app.route('/auth/facebook')
def facebook_auth():
    token = facebook.authorize_access_token()
    # Mengambil data user
    resp = facebook.get('me?fields=id,name,email')
    user_info = resp.json()
    
    # Logika Login/Register (Sama seperti Google)
    fb_email = user_info.get('email') # Kadang user menyembunyikan email di FB
    fb_name = user_info.get('name')
    fb_id = user_info.get('id')
    
    # Gunakan ID Facebook jika email tidak ada
    username_final = fb_email if fb_email else f"fb_{fb_id}"

    user = User.query.filter_by(username=username_final).first()
    if not user:
        # Buat user baru
        import secrets
        new_user = User(
            username=username_final,
            name=fb_name,
            password=generate_password_hash(secrets.token_hex(16))
        )
        db.session.add(new_user)
        db.session.commit()
        user = new_user

    login_user(user)
    return redirect(url_for('index'))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        name = request.form.get('name')
        password = request.form.get('password')

        # Cek apakah username sudah ada
        user = User.query.filter_by(username=username).first()

        if user:
            flash('Username sudah terdaftar.')
            return redirect(url_for('signup'))

        new_user = User(
            username=username,
            name=name,
            password=generate_password_hash(password)
        )
        
        db.session.add(new_user)
        db.session.commit()

        flash('Pendaftaran sukses! Silakan login.')
        return redirect(url_for('login'))

    return render_template('signup.html')

@app.route('/play', methods=['GET', 'POST'])
def play():
    if current_user.is_authenticated:
        return redirect(url_for('adventure_list'))
    
    if 'guest_messages' not in session:
        session['guest_messages'] = [
            {'sender': 'AI', 'content': 'Halo, Warga Asing! Anda memasukin zona bebas (Guest Mode). Silahkan berinteraksi, namun ingat jejak Anda akan hilang saat koneksi terputus.'}
        ]
    
    if request.method == 'POST':
        user_input = request.form.get('message')

        messages = session.get('guest_messages', [])

        messages.append({'sender': 'User', 'content': user_input})

        ai_reply = f"Sistem Tamu: Saya mendengar Anda berkata '{user_input}'. (Daftar akun untuk cerita lebih kompleks!)"
        messages.append({'sender': 'AI', 'content': ai_reply})

        session['guest_messages'] = messages
        session.modified = True

        return redirect(url_for('play'))

    return render_template('play.html', messages=session.get('guest_messages', []))

@app.route('/reset_guest')
def reset_guest():
    session.pop('guest_messages', None)
    return redirect(url_for('play'))

# Opsional: Route khusus untuk login sebagai tamu (redirect langsung)
@app.route('/guest_login')
def guest_login():
    flash('Anda masuk sebagai Warga Asing (Guest). Data tidak akan disimpan.', 'warning')
    return redirect(url_for('play'))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

# --- CONTOH API ---

@app.route('/api/users', methods=['GET'])
def get_all_users():
    users = User.query.all() # Ambil semua data
    output = []
    for user in users:
        output.append({
            'id': user.id,
            'username': user.username,
            'name': user.name
        })   
    return jsonify({'users': output})

@app.route('/api/me', methods=['GET'])
@login_required
def get_current_user_api():
    # API yang hanya bisa diakses jika sudah login
    return jsonify({
        'id': current_user.id, 
        'username': current_user.username,
        'name': current_user.name
    })

# TEMA: MODEL PETUALANGAN
class Adventure(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    character_name = db.Column(db.String(100), nullable=False)
    scenario = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Relasi ke Message
    messages = db.relationship('Message', backref='adventure', cascade="all, delete-orphan", lazy=True)

# TEMA: MODEL PESAN CHAT
class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    adventure_id = db.Column(db.Integer, db.ForeignKey('adventure.id'), nullable=False)
    sender = db.Column(db.String(50), nullable=False)  # 'user' atau 'ai'
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

@app.route('/adventures')
@login_required
def adventure_list():
    adventures = Adventure.query.filter_by(user_id=current_user.id).all()
    return render_template('adventure_list.html', adventures=adventures)

@app.route('/new_adventure', methods=['GET', 'POST'])
@login_required
def new_adventure():
    if request.method == 'POST':
        char_name = request.form.get('character_name')
        scenario = request.form.get('scenario')

        new_adv = Adventure(
            user_id=current_user.id,
            character_name=char_name,
            scenario=scenario
        )
        db.session.add(new_adv)
        db.session.commit()

        intro_msg = Message(
            adventure_id=new_adv.id,
            sender='AI',
            content=f"Selamat datang, {char_name}! Petualangan Anda dimulai di sini: {scenario}"
        )
        db.session.add(intro_msg)
        db.session.commit()

        return redirect(url_for('chat_room', adv_id=new_adv.id))

    return render_template('new_adventure.html')

@app.route('/chat/<int:adv_id>', methods=['GET', 'POST'])
@login_required
def chat_room(adv_id):
    adventure = Adventure.query.get_or_404(adv_id)

    if adventure.user_id != current_user.id:
        flash("Anda tidak memiliki akses ke petualangan ini.")
        return redirect(url_for('adventure_list'))
    
    if request.method == 'POST':
        user_input = request.form.get('message')

        user_msg = Message(adventure_id=adventure.id, sender='user', content=user_input)
        db.session.add(user_msg)

        ai_response_text = f"'Anda berkata: '{user_input}'. (AI sedang tidur, tapi cerita berlanjut...)"

        ai_msg = Message(adventure_id=adventure.id, sender='AI', content=ai_response_text)
        db.session.add(ai_msg)

        db.session.commit()

        return redirect(url_for('chat_room', adv_id=adv_id))
    
    return render_template('chat.html', adventure=adventure)

# --- TAMBAHAN: FITUR DELETE ADVENTURE ---
@app.route('/delete_adventure/<int:adv_id>', methods=['POST'])
@login_required
def delete_adventure(adv_id):
    # Cari petualangan berdasarkan ID
    adventure = Adventure.query.get_or_404(adv_id)
    
    # Keamanan: Cek apakah yang menghapus adalah pemiliknya
    if adventure.user_id != current_user.id:
        flash("Anda tidak berhak menghapus data ini.", "danger")
        return redirect(url_for('adventure_list'))
    
    # Hapus dari database
    db.session.delete(adventure)
    db.session.commit()
    
    flash("Petualangan berhasil dihapus.", "success")
    return redirect(url_for('adventure_list'))

# --- ROUTE GAME / ROLEPLAY WORLD ---

# --- UTILS ---

if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Membuat tabel database jika belum ada
    app.run(debug=True)
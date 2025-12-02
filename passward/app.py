from flask import Flask, request, jsonify, session, render_template
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import os
import json
from datetime import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-change-in-production'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///password_manager.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    master_hash = db.Column(db.String(255), nullable=False)
    salt = db.Column(db.String(255), nullable=False)

class Credential(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    site = db.Column(db.String(255), nullable=False)
    username = db.Column(db.String(255), nullable=False)
    password_ciphertext = db.Column(db.Text, nullable=False)
    notes = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

# Helper functions
def derive_key_from_password(password, salt):
    """Derive a key from password using PBKDF2"""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key

def encrypt_password(password, key):
    """Encrypt a password using Fernet"""
    f = Fernet(key)
    return f.encrypt(password.encode()).decode()

def decrypt_password(ciphertext, key):
    """Decrypt a password using Fernet"""
    f = Fernet(key)
    return f.decrypt(ciphertext.encode()).decode()

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    master_password = data.get('master_password')
    
    # Check if user already exists
    if User.query.first():
        return jsonify({'error': 'User already exists'}), 400
    
    # Generate salt and hash master password
    salt = os.urandom(16)
    key = derive_key_from_password(master_password, salt)
    
    # Store hash of master password (not the password itself)
    master_hash = generate_password_hash(master_password)
    
    user = User(master_hash=master_hash, salt=base64.b64encode(salt).decode())
    db.session.add(user)
    db.session.commit()
    
    # Store encryption key in session
    session['encryption_key'] = key.decode()
    
    return jsonify({'message': 'Registration successful'}), 201

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    master_password = data.get('master_password')
    
    user = User.query.first()
    if not user:
        return jsonify({'error': 'No user registered'}), 400
    
    # Check password
    if not check_password_hash(user.master_hash, master_password):
        return jsonify({'error': 'Invalid password'}), 401
    
    # Derive encryption key and store in session
    salt = base64.b64decode(user.salt)
    key = derive_key_from_password(master_password, salt)
    session['encryption_key'] = key.decode()
    
    return jsonify({'message': 'Login successful'}), 200

@app.route('/api/logout', methods=['POST'])
def logout():
    session.pop('encryption_key', None)
    return jsonify({'message': 'Logout successful'}), 200

@app.route('/api/credentials', methods=['GET'])
def get_credentials():
    if 'encryption_key' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    credentials = Credential.query.all()
    result = []
    for cred in credentials:
        result.append({
            'id': cred.id,
            'site': cred.site,
            'username': cred.username,
            'notes': cred.notes,
            'created_at': cred.created_at.isoformat(),
            'updated_at': cred.updated_at.isoformat()
        })
    return jsonify(result), 200

@app.route('/api/credentials', methods=['POST'])
def add_credential():
    if 'encryption_key' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    data = request.get_json()
    site = data.get('site')
    username = data.get('username')
    password = data.get('password')
    notes = data.get('notes')
    
    # Encrypt password
    key = session['encryption_key'].encode()
    encrypted_password = encrypt_password(password, key)
    
    credential = Credential(
        site=site,
        username=username,
        password_ciphertext=encrypted_password,
        notes=notes
    )
    
    db.session.add(credential)
    db.session.commit()
    
    return jsonify({
        'id': credential.id,
        'site': credential.site,
        'username': credential.username,
        'notes': credential.notes,
        'created_at': credential.created_at.isoformat(),
        'updated_at': credential.updated_at.isoformat()
    }), 201

@app.route('/api/credentials/<int:id>', methods=['GET'])
def get_credential(id):
    if 'encryption_key' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    credential = Credential.query.get_or_404(id)
    
    # Decrypt password
    key = session['encryption_key'].encode()
    decrypted_password = decrypt_password(credential.password_ciphertext, key)
    
    return jsonify({
        'id': credential.id,
        'site': credential.site,
        'username': credential.username,
        'password': decrypted_password,
        'notes': credential.notes,
        'created_at': credential.created_at.isoformat(),
        'updated_at': credential.updated_at.isoformat()
    }), 200

@app.route('/api/credentials/<int:id>', methods=['PUT'])
def update_credential(id):
    if 'encryption_key' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    credential = Credential.query.get_or_404(id)
    data = request.get_json()
    
    credential.site = data.get('site', credential.site)
    credential.username = data.get('username', credential.username)
    credential.notes = data.get('notes', credential.notes)
    
    # If password is being updated
    if 'password' in data:
        key = session['encryption_key'].encode()
        credential.password_ciphertext = encrypt_password(data['password'], key)
    
    credential.updated_at = datetime.utcnow()
    db.session.commit()
    
    return jsonify({
        'id': credential.id,
        'site': credential.site,
        'username': credential.username,
        'notes': credential.notes,
        'created_at': credential.created_at.isoformat(),
        'updated_at': credential.updated_at.isoformat()
    }), 200

@app.route('/api/credentials/<int:id>', methods=['DELETE'])
def delete_credential(id):
    if 'encryption_key' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    credential = Credential.query.get_or_404(id)
    db.session.delete(credential)
    db.session.commit()
    
    return jsonify({'message': 'Credential deleted'}), 200

@app.route('/api/export', methods=['GET'])
def export_data():
    if 'encryption_key' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    credentials = Credential.query.all()
    data = []
    for cred in credentials:
        data.append({
            'id': cred.id,
            'site': cred.site,
            'username': cred.username,
            'password_ciphertext': cred.password_ciphertext,
            'notes': cred.notes,
            'created_at': cred.created_at.isoformat(),
            'updated_at': cred.updated_at.isoformat()
        })
    
    return jsonify(data), 200

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
# Import necessary modules and libraries
from flask import Flask, render_template, request, jsonify, g
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

import os,binascii
import base64
import sqlite3
import threading

# Create a Flask web application instance to connect with the front end
app = Flask(__name__)

# SQLite database initialization
DATABASE = 'moramdb.db'

# Function to derive a key from a master password using PBKDF2HMAC by using SHA256 algorithm
# which is used to generate the key value while encrypting and decrypting
def derive_key(master_password):
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        iterations=100000,
        salt=salt,
        length=32,  # 32 bytes for AES-256
    )
    derived_key=kdf.derive(b"+master_password+")
    print(f"Derived Key Length: {len(derived_key)}")
    return derived_key

key= None
cipher= None
master_password = "kent"
iv_list=[]
row_count=0
salt = os.urandom(16)
key = derive_key(b'kent')
    
# Function to get the database connection
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
    return db

# Function to initialize the database schema
def init_db():
    with app.app_context():
        db = get_db()
        with app.open_resource('schema.sql', mode='r') as f:
            db.cursor().executescript(f.read())
        db.commit()

# Teardown function to close the database connection
@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

# Encryption function using AES256
def encrypt(plaintext, key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES256(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()
    return iv + ciphertext

# for decryption 
def decrypt(ciphertext, key):
    iv = ciphertext[:16]  # Extract the IV from the ciphertext
    cipher = Cipher(algorithms.AES256(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_text = decryptor.update(ciphertext[16:]) + decryptor.finalize()
    return decrypted_text.decode('latin-1', errors='replace')

# Function to store values as well as encrypted passwords into the database
def store_to_database(passwords):
    db = get_db()
    #encrypting the password before storing into database
    encrypted_password = encrypt(passwords[2], key)
    print(passwords)
    print("password= ",passwords[2],"  encrypted= ",encrypted_password,"decrypt= ", decrypt(encrypted_password, key))
    cursor = db.cursor()
    # inserting into database using sqlite query 
    cursor.execute('''
        INSERT INTO credentials (website, username, password)
        VALUES (?, ?, ?)
    ''', (passwords[0], passwords[1], encrypted_password))
    db.commit()
    cursor.execute('SELECT * FROM credentials')
    values = cursor.fetchall()
    print(values)

# Function to retrieve decrypted passwords from the database
def retrieve_from_database(key):
    db = get_db()
    cursor = db.cursor()
    cursor.execute('SELECT * FROM credentials')
    rows = cursor.fetchall()
    decrypted_credentials = []
    for row in rows:
        print("row= ",row,"\n")
        decrypted_password=decrypt(row[2],key)
        decrypted_credentials.append((row[0], row[1], decrypted_password))
    return decrypted_credentials

# Route for the home page so that the index.html page will appear on clicking the url
@app.route('/')
def index():
    return render_template('index.html')

# Route for authenticating the user
@app.route('/authenticate', methods=['POST'])
def authenticate():
    master_password = request.form['master_password']
    user_name = request.form['username']
    if master_password == 'lasya@99' and user_name == "lasya_moram":
        return render_template('dashboard.html')
    else:
        return 'Incorrect master password'

# Route for adding a new password
@app.route('/add_password', methods=['GET', 'POST'])
def add_password():
    print("inside addpassword method")
    passwords = []
    if request.method == 'POST':
        website = request.form['website']
        username = request.form['username']
        password = request.form['password']
        passwords.extend([website, username, password])
        print("password",passwords)
        store_to_database(passwords)
    return render_template('add_password1.html')

# Route for displaying stored passwords
@app.route('/display_password', methods=["POST", "GET"])
def display_password():
    global iv_list
    db = get_db()
    cursor = db.cursor()
    cursor.execute('SELECT * FROM credentials')
    passwords = cursor.fetchall()
    #print("passwords list in display paswords function ",passwords)
    print("iv-list ",iv_list)
    for i in passwords:
        print("decrypted password of row ",i[0]," = ",decrypt(i[3],key))
    password_list = [{'website': row[1], 'username': row[2], 'password': decrypt(row[3], key)} for row in passwords]
    return render_template('display_password.html', passwords=password_list)

# Run the Flask application
if __name__ == '__main__':
    init_db()
    app.run(debug=True)

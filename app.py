from flask import Flask, render_template, request, redirect, url_for, send_file, flash, jsonify
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.hazmat.primitives import padding, serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding, dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
from PIL import Image
import numpy as np
import os

# Set up Flask and login manager
website = Flask(__name__)
website.secret_key = "myVeryUniqueSecretKey888"

authenticator = LoginManager()
authenticator.init_app(website)
authenticator.login_view = "signin"

# Handles file uploads and outputs
FILE_DIR = "uploads"
OUTPUT_DIR = "result"
os.makedirs(FILE_DIR, exist_ok=True)
os.makedirs(OUTPUT_DIR, exist_ok=True)

# In-memory user store
people = {"admin": generate_password_hash("paswordpassword4321")}

# User and Loader
class Account(UserMixin):
    def __init__(self, identify):
        self.id = identify
    
@authenticator.user_loader
def get_acc(identify):
    if identify in people:
        return Account(identify)
    return None

# Read a file and return binary
def read_binfile(pathname):
    try:
        with open(pathname, "rb") as file:
            return file.read()
    except FileNotFoundError:
        return b""


# L value cyclically - steganography
def L_dynamic(idx):
    l = [8, 16, 28]
    return l[idx % len(l)]

# Embed a secret message in a carrier using LSB
def hide_message(carrier_path, file_path, result, start=0, step_length=8, mode_c=False):
    # Read carrier as raw bytes
    with open(carrier_path, "rb") as f:
        c_by = f.read()
    c_bits = ''.join(f"{b:08b}" for b in c_by)

    # Read secret payload
    msg = read_binfile(file_path)
    top = f"{len(msg):032b}"
    secret = ''.join(f"{b:08b}" for b in msg)
    payload = top + secret

    # Embed payload into carrier bits every L
    b = list(c_bits)
    index = 0
    pos = start
    while pos < len(b) and index < len(payload):
        b[pos] = payload[index]
        sp = L_dynamic(index) if mode_c else step_length
        pos += sp
        index += 1

    # Change list back to bytes
    mod = bytearray()
    for l in range(0, len(b), 8):
        b_chunk = b[l : l+8]
        if len(b_chunk) < 8:
            b_chunk += ["0"] * (8 - len(b_chunk))
        mod.append(int("".join(b_chunk), 2))
    
    # Write out steg file
    with open(result, "wb") as f:
        f.write(mod)
    
# Takes the hidden message from the image
def extr_msg(image_path, start=0, step_length=8, mode_c=False):
    # Read carrier as raw bytes
    with open(image_path, "rb") as f:
        c_by = f.read()
    c_bits = ''.join(f"{b:08b}" for b in c_by)

    # Extract 32-bit header for message length
    h_bits = ""
    idx = 0
    j = start
    for _ in range(32):
        if j >= len(c_bits): # Malformed
            return ""
        h_bits += c_bits[j]
        if mode_c:
            step = L_dynamic(idx)
        else:
            step = step_length
        j += step
        idx += 1

    try:
        msg_length = int(h_bits, 2)
    except ValueError:
        return ""

    # Take out msg_len * 8 bits for the message
    payload = ""
    total = msg_length * 8
    extr_bit = 0
    while j < len(c_bits) and extr_bit < total:
        payload += str(c_bits[j])
        step = L_dynamic(idx) if mode_c else step_length
        j += step
        idx += 1
        extr_bit += 1

    # Payload bit - multiple of 8 back to bytes
    chunks = [payload[i:i+8] for i in range(0, len(payload), 8)]
    data = bytearray(int(b, 2) for b in chunks if len(b) == 8)

    # Decode as UTF-8
    try:
        result = data.decode('utf-8')
    except Exception:
        result = data.decode('latin1')
    return result

# Symmetric Encryption

# AES Encryption with CBC and CTR padding; IV is prepended to ciphertext
def aes_encrypt(data: bytes, key: bytes, mode_name: str = "CBC") -> bytes:
    if mode_name == "CBC":
        initial = os.urandom(16)
        mode = modes.CBC(initial)
        # PKCS7 padding - block modes that need full blocks
        pad = padding.PKCS7(128).padder()
        data = pad.update(data) + pad.finalize()
        pre = initial
    elif mode_name == "CTR":
        initial = os.urandom(16)
        mode = modes.CTR(initial)
        # CTR doesn't need padding
        pre = initial
    else:
        raise ValueError(f"Unsupported AES mode: {mode_name}")

    c = Cipher(algorithms.AES(key), mode, backend=default_backend())
    encryptor = c.encryptor()
    ct = encryptor.update(data) + encryptor.finalize()
    return pre + ct

# Decrypt AES
def aes_decrypt(ciphertext: bytes, key: bytes, m_name: str = "CBC") -> bytes:
    initial = ciphertext[:16]
    ct = ciphertext[16:]

    # Choose between modes
    if m_name == "CBC":
        mode = modes.CBC(initial)
    elif m_name == "CTR":
        mode = modes.CTR(initial)
    else:
        raise ValueError(f"Unsupported AES mode: {m_name}")

    c = Cipher(algorithms.AES(key), mode, backend=default_backend())
    dec = c.decryptor()
    padded = dec.update(ct) + dec.finalize()

    if m_name == "CBC":
        # unpad only if CBC
        unp = padding.PKCS7(128).unpadder()
        info = unp.update(padded) + unp.finalize()
        return info
    else:
        return padded

# 3-DES encryption using CBC mode.
def triple_des_encrypt(info, key):
    # Ensure key length is 24 bytes (for 3DES)
    if len(key) < 24:
        key = key.ljust(24, b'\0')
    else:
        key = key[:24]

    # DES block size is 8 bytes
    initial = os.urandom(8)
    cipher = Cipher(algorithms.TripleDES(key), modes.CBC(initial), backend=default_backend())
    enc = cipher.encryptor()
    # 3DES block size - 64 bits
    pad= padding.PKCS7(64).padder()
    pad_data = pad.update(info) + pad.finalize()
    cipher_t = enc.update(pad_data) + enc.finalize()
    return initial + cipher_t

def triple_des_decrypt(c_text, key):
    if len(key) < 24:
        key = key.ljust(24, b'\0')
    else:
        key = key[:24]
    initial = c_text[:8]
    ct = c_text[8:]
    cipher = Cipher(algorithms.TripleDES(key), modes.CBC(initial), backend=default_backend())
    decr = cipher.decryptor()
    padded_data = decr.update(ct) + decr.finalize()
    unpadder = padding.PKCS7(64).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()
    return data

# Asymmetric Functions
# Generate RSA keypair (2048-bit)
def generate_rsa_keys():
    private_k = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    public_k = private_k.public_key()
    return private_k, public_k

# Serialize keys to PEM format
def serialize_private_key(key):
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

def serialize_public_key(key):
    return key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

# RSA encryption (for small data)
def rsa_encrypt(data, public_key):
    c_text = public_key.encrypt(
        data,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None))
    return c_text

def rsa_decrypt(c_text, private_key):
    p_text = private_key.decrypt(
        c_text,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None))
    return p_text

# SECURE HASHING FUNCTIONS
def compute_hash(info, choice='sha256'):
    if choice == 'sha256':
        dt = hashes.Hash(hashes.SHA256(), backend=default_backend())
    elif choice == 'sha3_256':
        dt = hashes.Hash(hashes.SHA3_256(), backend=default_backend())
    else:
        return None
    dt.update(info)
    return dt.finalize().hex()

# DIFFIE–HELLMAN KEY EXCHANGE
def diffie_hellman_demo():
    parameters = dh.generate_parameters(generator=2, key_size=512, backend=default_backend())
    private_key_1 = parameters.generate_private_key()
    private_key_2 = parameters.generate_private_key()
    shared_key_1 = private_key_1.exchange(private_key_2.public_key())
    shared_key_2 = private_key_2.exchange(private_key_1.public_key())
    # Derive a key (for example using HKDF) to show they match:
    derived_key_1 = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data',
        backend=default_backend()
    ).derive(shared_key_1)
    derived_key_2 = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data',
        backend=default_backend()
    ).derive(shared_key_2)
    return derived_key_1.hex(), derived_key_2.hex()

# User Authentication
# --- Routes for User Authentication and Registration ---
@website.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        user = request.form['username']
        psswd = request.form['password']
        if user in people:
            flash("User exists already!")
            return redirect(url_for("signup"))
        people[user] = generate_password_hash(psswd)
        flash("Account created! Log in.", "success")
        return redirect(url_for("signin"))
    return render_template('signup.html')

@website.route('/signin', methods=['GET', 'POST'])
def signin():
    if request.method == 'POST':
        user = request.form['username']
        psswd = request.form['password']
        if user in people and check_password_hash(people[user], psswd):
            login_user(Account(user))
            return redirect(url_for("home"))
        flash("Invalid credentials!", "danger")
        return redirect(url_for("signin"))
    return render_template('signin.html')

@website.route('/signout')
@login_required
def signout():
    logout_user()
    flash("Logged out!", "success")
    return redirect(url_for("home"))

# Main Website
@website.route('/')
def home():
    return render_template('index.html', user=current_user)

# Flask Routes : Steg
@website.route('/hide', methods=['POST'])
@login_required
def hide():
    # Expect a carrier image file and a secret message file from the form
    if 'image' not in request.files or 'message' not in request.files:
        return "Missing file!", 400
    image = request.files['image']
    secret_file = request.files['message']

    # Read additional parameters; use default if not provided
    try:
        start = int(request.form.get('start', 0))
        step_length = int(request.form.get('step_length', 8))
        mode_flag = request.form.get('mode_c', 'False').lower() in ['true', '1', 'yes']
    except Exception as e:
        return "Invalid parameters", 400
    
    # save carrier file
    carrier = os.path.join(FILE_DIR, image.filename)
    image.save(carrier)
    # save hidden msg temp
    hidden = os.path.join(FILE_DIR, "temp_secret.bin")
    secret_file.save(hidden)

    # Determine output filename: force a PNG extension
    base, ext = os.path.splitext(image.filename)
    output_name = f"{base}_steg{ext}"
    output_path = os.path.join(OUTPUT_DIR, output_name)
    
    hide_message(carrier, hidden, output_path, start=0, step_length=8, mode_c=True)
    return send_file(output_path, as_attachment=True)

@website.route('/extract', methods=['POST'])
def extract():
    if 'image' not in request.files:
        return "Missing file!", 400
    image = request.files['image']
    try:
        start = int(request.form.get('start', 0))
        step_length = int(request.form.get('step_length', 8))
        mode_flag = request.form.get('mode_c', 'False').lower() in ['true', '1', 'yes']
    except Exception as e:
        return "Invalid parameters", 400
    
    image_path = os.path.join(FILE_DIR, image.filename)
    image.save(image_path)
    secret_message = extr_msg(image_path, start=0, step_length=8, mode_c=True)
    return f"Extracted Message: {secret_message}"

@website.route('/steg')
@login_required
def steg_page():
    return render_template('steg.html')

# Flask : Symmetric Encryption - AES & DES
@website.route('/encrypt', methods=['POST'])
@login_required
def encrypt_file():
    if 'file' not in request.files or 'algorithm' not in request.form:
        return "Missing file or algorithm specification!", 400
    file = request.files['file']
    algo = request.form['algorithm']  # "AES-128", "AES-256", or "3DES"
    aes_mode = request.form.get('mode')
    info = file.read()

    if algo == "AES-128":
        k = os.urandom(16)
        encr = aes_encrypt(info, k, mode_name=aes_mode or "CBC")
    elif algo == "AES-256":
        k = os.urandom(32)
        encr = aes_encrypt(info, k, mode_name=aes_mode or "CBC")
    # 24 bytes for 3DES
    elif algo == "3DES":
        k = os.urandom(24)
        encr = triple_des_encrypt(info, k)
    else:
        return "Unsupported algorithm", 400
    
    # Build a filename that includes algo and mode for clarity
    filename = f"encrypted_{algo.replace('-', '')}"
    if algo.startswith("AES"):
        filename += f"_{aes_mode}"
    filename += f"_{file.filename}"
    output_path = os.path.join(OUTPUT_DIR, filename)

    # Final result
    # Save the ciphertext
    with open(output_path, "wb") as fout:
        fout.write(encr)

    # Prepare context for template
    key_hex = k.hex()
    download_url = url_for('download_file', filename=os.path.basename(output_path))

    # Render the same encrypt.html, now with key_hex & download_url
    return render_template(
        'encrypt.html',
        key_hex=key_hex,
        download_url=download_url
    )

@website.route('/decrypt', methods=['POST'])
@login_required
def decrypt_file():
    if 'file' not in request.files or 'key' not in request.form or 'algorithm' not in request.form:
        return "Missing file, key, or algorithm!", 400
    info = request.files['file']
    k_hex = request.form['key'].strip()
    aes_mode = request.form.get('mode', 'CBC')
    algo = request.form['algorithm']

    # Parse key
    try:
        key = bytes.fromhex(k_hex)
    except Exception as e:
        return "Invalid key format!", 400
    
    c_text = info.read()

    # Decrypt according to algo
    try:
        if algo in ["AES-128", "AES-256"]:
            decr = aes_decrypt(c_text, key, m_name=aes_mode or "CBC")
        elif algo == "3DES":
            decr = triple_des_decrypt(c_text, key)
        else:
            return "Unsupported algorithm", 400
    except Exception as err:
        return "Decryption failed: " + str(err), 400
    
    # Build output filename
    filename = f"decrypted_{algo.replace('-', '')}"
    if algo.startswith("AES"):
        filename += f"_{aes_mode}"
    filename += f"_{info.filename}"
    output_path = os.path.join(OUTPUT_DIR, filename)

    with open(output_path, "wb") as f_out:
        f_out.write(decr)

    flash("Decryption successful!")
    return send_file(output_path, as_attachment=True)

# Form to choose file, algorithm (AES-128, AES-256, 3DES)
@website.route('/encryption')
@login_required
def encryption_page():
    return render_template('encrypt.html')  

 # Form to select file, algorithm, and enter key (in hex)
@website.route('/decryption')
@login_required
def decryption_page():
    return render_template('decrypt.html') 

# Flask : Asymmetric encryption
# Generate RSA key pair and display serialized keys.
@website.route('/rsa_generate')
@login_required
def rsa_generate():
    private, public = generate_rsa_keys()
    private_pem = serialize_private_key(private).decode('utf-8')
    public_pem = serialize_public_key(public).decode('utf-8')

    # Keys are shown on the page for demo not real system
    return render_template('rsa.html', private_key=private_pem, public_key=public_pem)

# RSA encryption route: upload a file and encrypt with a provided public key.
@website.route('/rsa_encrypt', methods=['POST'])
@login_required
def rsa_encrypt_route():
    if 'file' not in request.files or 'pub_key' not in request.form:
        return "Missing file or public key!", 400
    file = request.files['file']
    public_pem = request.form['pub_key']
    info = file.read()
    try:
        public_key = load_pem_public_key(public_pem.encode('utf-8'), backend=default_backend())
    except Exception as e:
        return "Invalid public key!", 400
    try:
        encr = rsa_encrypt(info, public_key)
    except Exception as e:
        return "RSA encryption failed: " + str(e), 400
    o_path = os.path.join(OUTPUT_DIR, "rsa_encrypted_" + file.filename)
    with open(o_path, "wb") as fout:
        fout.write(encr)
    
    # Output message
    flash("RSA Encryption successful!")
    return send_file(o_path, as_attachment=True)

# RSA decryption route: upload a file and decrypt with a provided private key.
@website.route('/rsa_decrypt', methods=['POST'])
@login_required
def rsa_decrypt_route():
    if 'file' not in request.files or 'priv_key' not in request.form:
        return "Missing file or private key!", 400
    f = request.files['file']
    private_pem = request.form['priv_key']
    c_text = f.read()
    try:
        private_k = load_pem_private_key(private_pem.encode('utf-8'), password=None, backend=default_backend())
    except Exception as e:
        return "Invalid private key!", 400
    try:
        decrypted = rsa_decrypt(c_text, private_k)
    except Exception as e:
        return "RSA decryption failed: " + str(e), 400
    output_path = os.path.join(OUTPUT_DIR, "rsa_decrypted_" + f.filename)
    with open(output_path, "wb") as fout:
        fout.write(decrypted)

    flash("RSA Decryption successful!")
    return send_file(output_path, as_attachment=True)

# Page with forms for RSA key generation, encryption, decryption
@website.route('/rsa')
@login_required
def rsa_page():
    return render_template('rsa.html')

# Flask : Secure hashing

# Compute and display the hash of an uploaded file using chosen method.
@website.route('/hash', methods=['POST'])
@login_required
def file_hash():
    if 'file' not in request.files or 'method' not in request.form:
        return "Missing file or hash method!", 400
    f = request.files['file']
    
    # "sha256" or "sha3_256"
    method = request.form['method']
    info = f.read()
    h_val = compute_hash(info, method=method)
    return jsonify({"hash_method": method, "hash": h_val})

# DH Key Form
@website.route('/dh')
@login_required
def dh_demo():
    derived1, derived2 = diffie_hellman_demo()
    return render_template('dh.html', derived1=derived1, derived2=derived2)

# A form to upload a file and select the hash method
@website.route('/hash_page')
@login_required
def hash_page():
    return render_template('hash.html')

# File management
@website.route('/files')
def list_files():
    files = os.listdir(OUTPUT_DIR)
    return render_template('files.html', files=files)

@website.route('/download/<filename>')
def download_file(filename):
    return send_file(os.path.join(OUTPUT_DIR, filename), as_attachment=True)

if __name__ == '__main__':
    website.run(debug=True, port=8080)

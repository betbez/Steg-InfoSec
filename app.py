from flask import Flask, render_template, request, redirect, url_for, send_file, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from PIL import Image
import numpy as np
import os


website = Flask(__name__)
website.secret_key = "myVeryUniqueSecretKey888"

authenticator = LoginManager()
authenticator.init_app(website)
authenticator.login_view = "signin"

FILE_DIR = "uploads"
OUTPUT_DIR = "result"
os.makedirs(FILE_DIR, exist_ok=True)
os.makedirs(OUTPUT_DIR, exist_ok=True)

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
    with open(pathname, "rb") as file:
        return file.read()

# L value cyclically - steganography
def L_dynamic(idx):
    l = [8, 16, 28]
    return l[idx % len(l)]

# Embed a secret message in a carrier using LSB
def hide_message(carrier_path, file_path, result, start=0, step_length=8, mode_c=False):
    carrier = Image.open(carrier_path)
    carrier = carrier.convert("RGB")
    array_img = np.array(carrier)
    flat = array_img.flatten()

    msg = read_binfile(file_path)
    size = len(msg)

    header = format(size, '032b')
    secret = ''.join(format(b, '08b') for b in msg) # convert data to a string of bits

    # combine header and secret bits
    payload = header + secret
    msg_idx = 0
    index = 0
    i = start

    while i < len(flat) and msg_idx < len(payload):
        if mode_c:
            curr = L_dynamic(index)
        else:
            curr = step_length
        # overwrite pixel lsb with payload bit
        flat[i] = (flat[i] & ~1) | int(payload[msg_idx])
        msg_idx += 1
        i += curr
        index +=1
    
    # save modified image
    modified_image = flat.reshape(array_img.shape)
    Image.fromarray(modified_image).save(result, format='PNG')

# Takes the hidden message from the image
def extr_msg(image_path, start=0, step_length=8, mode_c=False):
    picture = Image.open(image_path)
    array_img = np.array(picture)
    flat = array_img.flatten()

    h_bits = ""
    idx = 0
    j = start
    for _ in range(32):
        h_bits += str(flat[j] & 1)
        if mode_c:
            step = L_dynamic(idx)
        else:
            step = step_length
        j += step
        idx += 1

    try:
        msg_length = int(h_bits, 2)
    except Exception:
        return ""

    # take out msg_len * 8 bits for the message
    payload = ""
    total = msg_length * 8
    extr_bit = 0
    while j < len(flat) and extr_bit < total:
        payload += str(flat[j] & 1)
        step = L_dynamic(idx) if mode_c else step_length
        j += step
        idx += 1
        extr_bit += 1

    # payload bit - multiple of 8
    number = len(payload) - (len(payload) % 8)
    payload = payload[:number]

    chunks = [payload[i:i+8] for i in range(0, len(payload), 8)]
    bytes = bytearray(int(b, 2) for b in chunks)
    try:
        result = bytes.decode('utf-8')
    except Exception:
        result = bytes.decode('latin1')
    return result

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

@website.route('/hide', methods=['POST'])
@login_required
def hide():
    # Expecting a carrier image file and a secret message file from the form
    if 'image' not in request.files or 'message' not in request.files:
        return "Missing file(s)!", 400
    image = request.files['image']
    secret_file = request.files['message']
    
    # save carrier file
    carrier = os.path.join(FILE_DIR, image.filename)
    image.save(carrier)
    # save hidden msg temp
    hidden = os.path.join(FILE_DIR, "temp_secret.bin")
    secret_file.save(hidden)

    # Determine output filename: force a PNG extension
    base, ext = os.path.splitext(image.filename)
    output = os.path.join(OUTPUT_DIR, base + "_steg.png")
    
    hide_message(carrier, hidden, output, start=0, step_length=8, mode_c=True)
    return send_file(output, as_attachment=True)

@website.route('/extract', methods=['POST'])
def extract():
    if 'image' not in request.files:
        return "Missing file!", 400
    image = request.files['image']
    image_path = os.path.join(FILE_DIR, image.filename)
    image.save(image_path)
    secret_message = extr_msg(image_path, start=0, step_length=8, mode_c=True)
    return f"Extracted Message: {secret_message}"

@website.route('/files')
def list_files():
    files = os.listdir(OUTPUT_DIR)
    return render_template('files.html', files=files)

@website.route('/download/<filename>')
def download_file(filename):
    return send_file(os.path.join(OUTPUT_DIR, filename), as_attachment=True)

if __name__ == '__main__':
    website.run(debug=True, port=5008)
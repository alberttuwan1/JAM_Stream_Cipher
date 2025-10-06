from flask import Blueprint, render_template, request, send_file, redirect, url_for
from flask_login import login_required
import os
from cipher.jam_cipher import JAMStreamCipherBytes

cipher_bp = Blueprint("cipher", __name__, url_prefix="/cipher")

@cipher_bp.route("/encrypt", methods=["GET", "POST"])
@login_required
def encrypt():
    if request.method == "POST":
        file = request.files["file"]
        seed = int(request.form["seed"])
        action = request.form["action"]

        data = file.read()
        cipher = JAMStreamCipherBytes(seed=seed)

        if action == "encrypt":
            result = cipher.encrypt(data)
            filename = "encrypted_" + file.filename
        else:
            result = cipher.decrypt(data)
            filename = "decrypted_" + file.filename

        os.makedirs("uploads", exist_ok=True)
        path = os.path.join("uploads", filename)
        with open(path, "wb") as f:
            f.write(result)

        return send_file(path, as_attachment=True)

    return render_template("encrypt.html")

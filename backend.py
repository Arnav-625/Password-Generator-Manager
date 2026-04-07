from flask import Flask, request, jsonify
from flask_cors import CORS
import subprocess

app = Flask(__name__)
CORS(app)  

@app.route("/")
def home():
    return "Password backend running"

@app.route("/generate", methods=["POST"])
def generate():
    email = request.json["email"]
    length = request.json.get("length", 16)

    proc = subprocess.Popen(
        ["./password_app"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        text=True
    )

    output = proc.communicate(f"1\n{email}\n{length}\n")[0]

    password = output.strip()

    return jsonify({"password": password})

@app.route("/search", methods=["POST"])
def search():
    email = request.json["email"]

    proc = subprocess.Popen(
        ["./password_app"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        text=True
    )

    output = proc.communicate(f"2\n{email}\n")[0].strip()

    if output == "NOT_FOUND":
        password = "Not Found"
    else:
        password = output

    return jsonify({"password": password})

if __name__ == "__main__":
    app.run(port=5000)

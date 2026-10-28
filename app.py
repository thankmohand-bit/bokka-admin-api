from flask import Flask, jsonify, send_from_directory

app = Flask(__name__)

@app.route("/")
def home():
    return send_from_directory(".", "admin.html")

@app.route("/api/status")
def status():
    return jsonify({
        "status": "success",
        "message": "BOKKA FOX Admin API is running"
    })

@app.route("/health")
def health():
    return jsonify({"status": "ok"})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=10000)

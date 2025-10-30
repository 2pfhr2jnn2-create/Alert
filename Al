import os
import requests
from flask import Flask, request, jsonify

app = Flask(__name__)

TELEGRAM_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")

def send_to_telegram(text: str):
    if not TELEGRAM_TOKEN or not TELEGRAM_CHAT_ID:
        return {"ok": False, "error": "Missing TELEGRAM_BOT_TOKEN or TELEGRAM_CHAT_ID"}
    url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
    payload = {"chat_id": TELEGRAM_CHAT_ID, "text": text}
    try:
        r = requests.post(url, json=payload, timeout=10)
        return r.json()
    except Exception as e:
        return {"ok": False, "error": str(e)}

@app.route("/health", methods=["GET"])
def health():
    return "ok", 200

# Pour tester depuis Safari sans outil spécial :
# https://ton-service.onrender.com/send_test?msg=Hello
@app.route("/send_test", methods=["GET", "POST"])
def send_test():
    if request.method == "POST":
        data = request.get_json(silent=True) or {}
        text = data.get("msg", "Test Render (POST)")
    else:
        text = request.args.get("msg", "Test Render (GET)")
    result = send_to_telegram(text)
    code = 200 if result.get("ok", False) else 500
    return jsonify(result), code

# Render lance via gunicorn (voir Procfile), mais garder ceci pour exécution locale
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))

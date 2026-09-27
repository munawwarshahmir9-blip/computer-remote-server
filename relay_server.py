from flask import Flask, request, jsonify
import secrets
import time
import threading

app = Flask(__name__)

# Temporary pairing codes
pairing_codes = {}

# Paired PC sessions
paired_pcs = {}

LOCK = threading.Lock()

PAIRING_CODE_LIFETIME = 10 * 60  # 10 minutes


def generate_pairing_code():
    return f"{secrets.randbelow(1000000):06d}"


def cleanup_codes():
    now = time.time()

    with LOCK:
        expired = [
            code
            for code, data in pairing_codes.items()
            if now > data["expires"]
        ]

        for code in expired:
            del pairing_codes[code]


@app.route("/", methods=["GET"])
def home():
    return jsonify({
        "service": "Computer Remote Relay Server",
        "status": "online"
    })


@app.route("/status", methods=["GET"])
def status():
    return jsonify({
        "status": "online",
        "service": "computer-remote-relay"
    })


@app.route("/register_pc", methods=["POST"])
def register_pc():
    cleanup_codes()

    data = request.get_json(silent=True) or {}

    pc_id = data.get("pc_id")

    if not pc_id:
        pc_id = secrets.token_urlsafe(24)

    pairing_code = generate_pairing_code()

    pc_token = secrets.token_urlsafe(32)

    with LOCK:
        pairing_codes[pairing_code] = {
            "pc_id": pc_id,
            "pc_token": pc_token,
            "expires": time.time() + PAIRING_CODE_LIFETIME
        }

        paired_pcs[pc_id] = {
            "pc_token": pc_token,
            "phone_token": None,
            "created": time.time()
        }

    return jsonify({
        "success": True,
        "pc_id": pc_id,
        "pairing_code": pairing_code,
        "expires_in": PAIRING_CODE_LIFETIME
    })


@app.route("/pair", methods=["POST"])
def pair():
    cleanup_codes()

    data = request.get_json(silent=True) or {}

    pairing_code = data.get("pairing_code")

    if not pairing_code:
        return jsonify({
            "success": False,
            "error": "pairing_code_required"
        }), 400

    with LOCK:
        info = pairing_codes.get(pairing_code)

        if not info:
            return jsonify({
                "success": False,
                "error": "invalid_or_expired_code"
            }), 401

        pc_id = info["pc_id"]
        pc_token = info["pc_token"]

        phone_token = secrets.token_urlsafe(32)

        paired_pcs[pc_id]["phone_token"] = phone_token

        del pairing_codes[pairing_code]

    return jsonify({
        "success": True,
        "pc_id": pc_id,
        "phone_token": phone_token
    })


@app.route("/pc_check", methods=["POST"])
def pc_check():
    data = request.get_json(silent=True) or {}

    pc_id = data.get("pc_id")
    pc_token = data.get("pc_token")

    with LOCK:
        pc = paired_pcs.get(pc_id)

        if not pc:
            return jsonify({
                "success": False,
                "error": "pc_not_found"
            }), 404

        if not secrets.compare_digest(
            str(pc["pc_token"]),
            str(pc_token)
        ):
            return jsonify({
                "success": False,
                "error": "invalid_pc_token"
            }), 401

    return jsonify({
        "success": True,
        "paired": pc["phone_token"] is not None
    })


@app.route("/phone_check", methods=["POST"])
def phone_check():
    data = request.get_json(silent=True) or {}

    pc_id = data.get("pc_id")
    phone_token = data.get("phone_token")

    with LOCK:
        pc = paired_pcs.get(pc_id)

        if not pc:
            return jsonify({
                "success": False,
                "error": "pc_not_found"
            }), 404

        if not pc["phone_token"]:
            return jsonify({
                "success": False,
                "error": "pc_not_paired"
            }), 401

        if not secrets.compare_digest(
            str(pc["phone_token"]),
            str(phone_token)
        ):
            return jsonify({
                "success": False,
                "error": "invalid_phone_token"
            }), 401

    return jsonify({
        "success": True,
        "paired": True
    })


if __name__ == "__main__":
    print("=" * 50)
    print("COMPUTER REMOTE INTERNET RELAY")
    print("=" * 50)
    print("Server starting...")
    print("Local test: http://127.0.0.1:5000")
    print("=" * 50)

    app.run(
        host="0.0.0.0",
        port=5000,
        debug=False
    )
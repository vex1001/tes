import os
import uuid
import threading
import time
import re
import requests
from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
from functools import wraps

app = Flask(__name__)

# SECURITY: Restrict CORS to your domain only
# Change this to your actual domain when deploying
ALLOWED_ORIGINS = [
    "https://kyocheats.xyz",
    "https://www.kyocheats.xyz",
    "http://localhost:5500",  # For local testing
    "http://127.0.0.1:5500"
]
CORS(app, origins=ALLOWED_ORIGINS)

# Rate limiting storage
rate_limits = {}  # IP -> {attempts: int, last_attempt: timestamp}
RATE_LIMIT_MAX = 5
RATE_LIMIT_WINDOW = 60  # seconds

def get_client_ip():
    """Get real client IP, accounting for proxies"""
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    return request.remote_addr

def rate_limit(f):
    """Rate limiting decorator"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        ip = get_client_ip()
        now = time.time()
        
        if ip in rate_limits:
            data = rate_limits[ip]
            # Reset if window expired
            if now - data['last_attempt'] > RATE_LIMIT_WINDOW:
                rate_limits[ip] = {'attempts': 1, 'last_attempt': now}
            elif data['attempts'] >= RATE_LIMIT_MAX:
                return jsonify({"error": "Too many requests. Please wait."}), 429
            else:
                data['attempts'] += 1
                data['last_attempt'] = now
        else:
            rate_limits[ip] = {'attempts': 1, 'last_attempt': now}
        
        return f(*args, **kwargs)
    return decorated_function

def sanitize_key(key):
    """Sanitize license key input"""
    if not key or not isinstance(key, str):
        return None
    # Only allow alphanumeric, hyphens, underscores
    sanitized = re.sub(r'[^a-zA-Z0-9\-_]', '', key)
    # Limit length
    return sanitized[:64] if len(sanitized) >= 8 else None

# Per-session progress tracking
downloads = {}
DOWNLOAD_DIR = os.path.join(os.path.expanduser('~'), 'Downloads')

def start_invisible_download(download_id, license_key):
    prog = downloads[download_id]
    session = requests.Session()
    base_url = "https://loader.cryptauth.net"

    try:
        # Step 1: Validate License
        prog.update({"status": "working", "message": "Verifying License..."})
        check_res = session.post(f"{base_url}/check_license.php", 
                                 data={"license": license_key}, 
                                 headers={"Content-Type": "application/x-www-form-urlencoded"})
        
        data = check_res.json()
        
        if data.get("status") != "valid":
            prog.update({"status": "error", "message": data.get("message", "Invalid Key")})
            return

        app_id = data.get("app_id")
        
        # Step 2: Request Download
        prog.update({"message": "Authorized. Fetching Binary..."})
        dl_res = session.post(f"{base_url}/download.php", 
                              data={"app_id": app_id}, 
                              stream=True)

        if dl_res.status_code != 200:
            prog.update({"status": "error", "message": "Server rejected download request"})
            return

        # Get file info
        total_length = int(dl_res.headers.get('content-length', 0))
        filename = f"{download_id}.exe"
        
        save_path = os.path.join(DOWNLOAD_DIR, filename)
        prog["filename"] = filename
        
        # Step 3: Stream and Save (This is where the % happens)
        prog["status"] = "downloading"
        dl_size = 0
        with open(save_path, "wb") as f:
            for chunk in dl_res.iter_content(chunk_size=4096):
                if chunk:
                    f.write(chunk)
                    dl_size += len(chunk)
                    if total_length > 0:
                        percent = int((dl_size / total_length) * 100)
                        prog["percentage"] = percent
                        prog["message"] = f"Transferring: {percent}%"

        prog.update({"percentage": 100, "status": "complete", "message": "Loader Downloaded Successfully"})

    except Exception as e:
        prog.update({"status": "error", "message": "Connection Error"})

@app.route('/start-download', methods=['POST'])
@rate_limit
def start():
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "Invalid request"}), 400
        
        raw_key = data.get('key')
        key = sanitize_key(raw_key)
        
        if not key:
            return jsonify({"error": "Invalid key format"}), 400
        
        download_id = str(uuid.uuid4())
        downloads[download_id] = {
            "percentage": 0, 
            "status": "starting", 
            "message": "Connecting...", 
            "filename": None,
            "created_at": time.time()
        }
        threading.Thread(target=start_invisible_download, args=(download_id, key)).start()
        return jsonify({"status": "processing", "download_id": download_id})
    except Exception as e:
        return jsonify({"error": "Server error"}), 500

@app.route('/progress/<download_id>')
def get_progress(download_id):
    # Validate download_id format (UUID)
    if not re.match(r'^[a-f0-9\-]{36}$', download_id):
        return jsonify({"percentage": 0, "status": "error", "message": "Invalid session"}), 400
    
    prog = downloads.get(download_id)
    if not prog:
        return jsonify({"percentage": 0, "status": "error", "message": "Session not found"}), 404
    
    # Don't expose internal fields
    return jsonify({
        "percentage": prog.get("percentage", 0),
        "status": prog.get("status", "unknown"),
        "message": prog.get("message", "")
    })

@app.route('/download-file/<download_id>')
def download_file(download_id):
    # Validate download_id format (UUID)
    if not re.match(r'^[a-f0-9\-]{36}$', download_id):
        return jsonify({"error": "Invalid session"}), 400
    
    prog = downloads.get(download_id)
    if not prog or not prog.get("filename"):
        return jsonify({"error": "File not found"}), 404
    
    # Security: Ensure filename is safe (no path traversal)
    filename = os.path.basename(prog["filename"])
    path = os.path.join(DOWNLOAD_DIR, filename)
    
    # Verify path is within DOWNLOAD_DIR
    if not os.path.abspath(path).startswith(os.path.abspath(DOWNLOAD_DIR)):
        return jsonify({"error": "Access denied"}), 403
    
    if os.path.exists(path):
        response = send_file(path, as_attachment=True, download_name="loader.exe")
        # Clean up after download
        threading.Thread(target=cleanup_download, args=(download_id, path)).start()
        return response
    return jsonify({"error": "File not found"}), 404

def cleanup_download(download_id, filepath):
    """Clean up download files after a delay"""
    time.sleep(30)  # Wait 30 seconds before cleanup
    try:
        if os.path.exists(filepath):
            os.remove(filepath)
        if download_id in downloads:
            del downloads[download_id]
    except:
        pass

# Valorant updates cache
val_cache = {"data": None, "timestamp": 0}

@app.route('/valorant-updates')
def valorant_updates():
    import time
    now = time.time()
    if val_cache["data"] and (now - val_cache["timestamp"]) < 600:
        return jsonify(val_cache["data"])
    try:
        r = requests.get("https://data.rito.news/val/en-us/news.json", timeout=10)
        all_news = r.json()
        patches = [item for item in all_news if "Game Updates" in item.get("categories", []) and "Patch Notes" in item.get("title", "")][:5]
        result = []
        for p in patches:
            result.append({
                "title": p.get("title", ""),
                "description": p.get("description", ""),
                "date": p.get("date", ""),
                "url": p.get("url", ""),
                "image": p.get("image", "")
            })
        val_cache["data"] = result
        val_cache["timestamp"] = now
        return jsonify(result)
    except Exception:
        return jsonify([])

# Periodic cleanup of old sessions
def cleanup_old_sessions():
    while True:
        time.sleep(300)  # Every 5 minutes
        now = time.time()
        expired = [k for k, v in downloads.items() if now - v.get('created_at', 0) > 600]
        for k in expired:
            prog = downloads.get(k)
            if prog and prog.get('filename'):
                filepath = os.path.join(DOWNLOAD_DIR, prog['filename'])
                try:
                    if os.path.exists(filepath):
                        os.remove(filepath)
                except:
                    pass
            downloads.pop(k, None)

if __name__ == '__main__':
    # Start cleanup thread
    cleanup_thread = threading.Thread(target=cleanup_old_sessions, daemon=True)
    cleanup_thread.start()
    
    # For production, use: gunicorn -w 4 -b 0.0.0.0:5000 main:app
    app.run(port=5000, host='0.0.0.0')

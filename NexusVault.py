#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
 ██████╗ ██╗  ██╗███████╗██╗   ██╗ █████╗ ██╗     ██╗   ██╗███████╗██████╗ 
██╔════╝ ██║  ██║██╔════╝╚██╗ ██╔╝██╔══██╗██║     ██║   ██║██╔════╝██╔══██╗
██║  ███╗███████║█████╗   ╚████╔╝ ███████║██║     ██║   ██║█████╗  ██████╔╝
██║   ██║██╔══██║██╔══╝    ╚██╔╝  ██╔══██║██║     ██║   ██║██╔══╝  ██╔══██╗
╚██████╔╝██║  ██║███████╗   ██║   ██║  ██║███████╗╚██████╔╝███████╗██║  ██║
 ╚═════╝ ╚═╝  ╚═╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝

            🔒 NEXUSVAULT — Secure, Modern, Cross-Platform File Nexus
            ✦ Developed by: Ahmed Noor Ahmed (Qena, Egypt) ✦
            ✦ Version: 1.0.0 | License: MIT ✦
            ✦ Icon: NexusVault.png (place in same dir or auto-fallback) ✦
"""

import os
import sys
import re
import json
import hashlib
import secrets
import asyncio
import webbrowser
import threading
import zipfile
import mimetypes
import qrcode
import base64
from datetime import datetime
from pathlib import Path
from urllib.parse import quote

import uvicorn
from fastapi import FastAPI, File, UploadFile, HTTPException, Request, BackgroundTasks
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from jinja2 import Template

try:
    from PyQt6.QtWidgets import (
        QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
        QLabel, QLineEdit, QSpinBox, QTabWidget, QTableWidget, QTableWidgetItem,
        QHeaderView, QMessageBox, QFileDialog, QSystemTrayIcon, QMenu, QTextEdit,
        QSplitter, QCheckBox, QGroupBox, QComboBox
    )
    from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer, QUrl, QSize
    from PyQt6.QtGui import QIcon, QPixmap, QDesktopServices, QFont, QColor, QPalette
    from PyQt6.QtWebEngineWidgets import QWebEngineView
except ImportError:
    print("[!] PyQt6 not found. Installing minimal fallback (CLI mode only)...")
    print("👉 Run: pip install pyqt6 pyqt6-webengine fastapi uvicorn python-multipart jinja2 qrcode pillow")
    sys.exit(1)

# ==============================
# CONFIG & PATHS
# ==============================
BASE_DIR = Path(__file__).parent.resolve()
UPLOADS_DIR = BASE_DIR / "uploads"
LOGS_DIR = BASE_DIR / "logs"
METADATA_FILE = LOGS_DIR / "uploads.json"
CONFIG_FILE = BASE_DIR / "nexusvault_config.json"

UPLOADS_DIR.mkdir(exist_ok=True)
LOGS_DIR.mkdir(exist_ok=True)

# Default config
DEFAULT_CONFIG = {
    "port": 8080,
    "host": "0.0.0.0",
    "max_file_size_mb": 100,
    "allowed_extensions": "*",
    "enable_encryption": False,
    "encryption_key": "",
    "auto_open_browser": True,
    "dark_mode": True,
    "enable_qr": True,
    "enable_zip_batch": True
}

# Load or init config
if CONFIG_FILE.exists():
    try:
        with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
            config = json.load(f)
        # Backward compat
        for k, v in DEFAULT_CONFIG.items():
            config.setdefault(k, v)
    except:
        config = DEFAULT_CONFIG.copy()
else:
    config = DEFAULT_CONFIG.copy()
    with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
        json.dump(config, f, indent=2)

# ==============================
# FASTAPI APP (Backend Server)
# ==============================
app = FastAPI(title="NexusVault API", description="Ahmed Noor Ahmed's Secure File Transfer Hub")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory upload log (sync with file)
upload_log = []

def load_upload_log():
    global upload_log
    if METADATA_FILE.exists():
        try:
            with open(METADATA_FILE, 'r', encoding='utf-8') as f:
                upload_log = json.load(f)
        except:
            upload_log = []
    else:
        upload_log = []

def save_upload_log():
    try:
        with open(METADATA_FILE, 'w', encoding='utf-8') as f:
            json.dump(upload_log, f, indent=2, default=str)
    except Exception as e:
        print(f"[LOG ERROR] {e}")

load_upload_log()

class UploadResponse(BaseModel):
    success: bool
    filename: str
    size: int
    url: str
    sha256: str
    timestamp: str

def sanitize_filename(name: str) -> str:
    # Remove path traversal & unsafe chars
    name = re.sub(r'[<>:"/\\|?*\x00-\x1f]', '_', name)
    name = name.strip('. ')
    return name or "unnamed_file"

@app.get("/", response_class=HTMLResponse)
async def serve_upload_page():
    return get_upload_html()

@app.post("/upload")
async def upload_file(file: UploadFile = File(...)):
    if not file.filename:
        raise HTTPException(status_code=400, detail="No file selected")
    
    # Size check
    max_bytes = config["max_file_size_mb"] * 1024 * 1024
    try:
        content = await file.read()
        if len(content) > max_bytes:
            raise HTTPException(status_code=413, detail=f"File too large (> {config['max_file_size_mb']} MB)")
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Read error: {e}")

    safe_name = sanitize_filename(file.filename)
    ext = Path(safe_name).suffix.lower().lstrip('.')
    
    # Extension whitelist (if not "*")
    if config["allowed_extensions"] != "*" and ext not in config["allowed_extensions"].split(','):
        raise HTTPException(status_code=400, detail=f"Extension .{ext} not allowed")

    # Deduplication via SHA-256
    sha256_hash = hashlib.sha256(content).hexdigest()
    existing = next((item for item in upload_log if item.get("sha256") == sha256_hash), None)
    if existing:
        # Return existing file URL
        return UploadResponse(
            success=True,
            filename=existing["filename"],
            size=existing["size"],
            url=f"/files/{quote(existing['filename'])}",
            sha256=sha256_hash,
            timestamp=existing["timestamp"]
        )

    # Save file
    final_path = UPLOADS_DIR / safe_name
    # Avoid overwrite: add counter if exists
    counter = 1
    stem = Path(safe_name).stem
    suffix = Path(safe_name).suffix
    while final_path.exists():
        safe_name = f"{stem}__{counter}{suffix}"
        final_path = UPLOADS_DIR / safe_name
        counter += 1

    try:
        with open(final_path, "wb") as f:
            f.write(content)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Write failed: {e}")

    # Log
    record = {
        "filename": safe_name,
        "original_name": file.filename,
        "size": len(content),
        "sha256": sha256_hash,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "ip": "0.0.0.0",  # Will be overridden by middleware
        "mime": file.content_type or mimetypes.guess_type(safe_name)[0] or "application/octet-stream"
    }
    upload_log.append(record)
    save_upload_log()

    return UploadResponse(
        success=True,
        filename=safe_name,
        size=len(content),
        url=f"/files/{quote(safe_name)}",
        sha256=sha256_hash,
        timestamp=record["timestamp"]
    )

@app.get("/files/{filename}")
async def get_file(filename: str):
    safe_name = sanitize_filename(filename)
    file_path = UPLOADS_DIR / safe_name
    if not file_path.exists():
        raise HTTPException(status_code=404, detail="File not found")
    return FileResponse(file_path, filename=safe_name)

@app.get("/api/files")
async def list_files():
    return JSONResponse(upload_log)

@app.delete("/api/files/{filename}")
async def delete_file(filename: str):
    safe_name = sanitize_filename(filename)
    file_path = UPLOADS_DIR / safe_name
    if file_path.exists():
        try:
            file_path.unlink()
            global upload_log
            upload_log = [f for f in upload_log if f["filename"] != safe_name]
            save_upload_log()
            return {"success": True, "message": f"Deleted: {safe_name}"}
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    else:
        raise HTTPException(status_code=404, detail="File not found")

@app.get("/api/qr/{filename}")
async def get_qr_code(filename: str):
    safe_name = sanitize_filename(filename)
    url = f"http://{get_local_ip()}:{config['port']}/files/{quote(safe_name)}"
    qr = qrcode.make(url, box_size=10, border=4)
    qr_bytes = qr.tobytes()
    return HTMLResponse(
        f"""
        <html><body style="text-align:center;background:#1e1e1e;color:#00ff88">
        <h2>🔗 Share Link</h2>
        <p><b>{url}</b></p>
        <img src="image/png;base64,{base64.b64encode(qr_bytes).decode()}" alt="QR"/>
        <br><br>
        <button onclick="window.close()">Close</button>
        </body></html>
        """
    )

@app.get("/api/download/zip")
async def download_zip(filenames: str):
    # filenames = "file1.txt,file2.jpg"
    name_list = [sanitize_filename(n) for n in filenames.split(',') if n.strip()]
    if not name_list:
        raise HTTPException(status_code=400, detail="No files specified")

    zip_path = LOGS_DIR / f"batch_{secrets.token_hex(4)}.zip"
    try:
        with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for name in name_list:
                fp = UPLOADS_DIR / name
                if fp.exists():
                    zipf.write(fp, arcname=name)
        return FileResponse(zip_path, filename="NexusVault_Batch.zip", media_type="application/zip")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        # Cleanup zip after download (optional background)
        pass

@app.middleware("http")
async def add_ip_to_log(request: Request, call_next):
    # Inject IP into last upload (crude but works for single-user)
    response = await call_next(request)
    client_ip = request.client.host if request.client else "unknown"
    if request.url.path == "/upload" and upload_log:
        upload_log[-1]["ip"] = client_ip
        save_upload_log()
    return response

# Serve static for favicon (if NexusVault.png exists)
if (BASE_DIR / "NexusVault.png").exists():
    app.mount("/static", StaticFiles(directory=str(BASE_DIR)), name="static")

# ==============================
# EMBEDDED FRONTEND (HTML/JS/CSS)
# ==============================
def get_upload_html():
    return f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NexusVault • File Nexus</title>
    <link rel="icon" href="/static/NexusVault.png" type="image/png">
    <style>
        :root {{
            --bg: #0f0f1b;
            --card: #1a1a2e;
            --primary: #00f7ff;
            --secondary: #ff00c8;
            --text: #e0e0ff;
            --danger: #ff4d7a;
            --success: #00ffaa;
        }}
        * {{ margin:0; padding:0; box-sizing:border-box; }}
        body {{
            background: var(--bg);
            color: var(--text);
            font-family: 'Segoe UI', system-ui, sans-serif;
            padding: 2rem;
            min-height: 100vh;
        }}
        .container {{
            max-width: 900px;
            margin: 0 auto;
        }}
        header {{
            text-align: center;
            margin-bottom: 2rem;
        }}
        h1 {{
            font-size: 2.8rem;
            background: linear-gradient(90deg, var(--primary), var(--secondary));
            -webkit-background-clip: text;
            background-clip: text;
            color: transparent;
            margin-bottom: 0.5rem;
        }}
        .subtitle {{
            opacity: 0.7;
            font-size: 1.1rem;
        }}
        .card {{
            background: var(--card);
            border-radius: 16px;
            padding: 1.8rem;
            margin-bottom: 1.5rem;
            box-shadow: 0 10px 30px rgba(0,0,0,0.5);
            border: 1px solid rgba(0,247,255,0.1);
        }}
        .upload-area {{
            border: 3px dashed var(--primary);
            border-radius: 12px;
            padding: 3rem 2rem;
            text-align: center;
            transition: all 0.3s;
            cursor: pointer;
            position: relative;
        }}
        .upload-area:hover {{
            border-color: var(--secondary);
            background: rgba(0,247,255,0.03);
        }}
        .upload-area i {{
            font-size: 3.5rem;
            margin-bottom: 1rem;
            color: var(--primary);
        }}
        .upload-area h3 {{
            font-size: 1.6rem;
            margin-bottom: 0.5rem;
        }}
        .upload-area p {{
            opacity: 0.8;
        }}
        #file-input {{
            display: none;
        }}
        .btn {{
            background: linear-gradient(90deg, #00c1ff, #0077ff);
            color: white;
            border: none;
            padding: 0.75rem 1.5rem;
            border-radius: 8px;
            font-weight: 600;
            cursor: pointer;
            transition: 0.2s;
        }}
        .btn:hover {{
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(0,119,255,0.4);
        }}
        .btn-danger {{
            background: var(--danger);
        }}
        .progress {{
            height: 8px;
            background: #333;
            border-radius: 4px;
            margin: 1rem 0;
            overflow: hidden;
        }}
        .progress-bar {{
            height: 100%;
            background: var(--success);
            width: 0%;
            transition: width 0.3s;
        }}
        #file-list {{
            width: 100%;
            border-collapse: collapse;
        }}
        #file-list th {{
            text-align: left;
            padding: 0.75rem;
            border-bottom: 1px solid #333;
        }}
        #file-list td {{
            padding: 0.75rem;
            border-bottom: 1px solid #2a2a3e;
            font-size: 0.95rem;
        }}
        .actions a {{
            margin-right: 10px;
            text-decoration: none;
            color: var(--primary);
        }}
        .actions a:hover {{
            text-decoration: underline;
        }}
        .tag {{
            display: inline-block;
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 0.75rem;
            background: rgba(0,247,255,0.15);
            color: var(--primary);
        }}
        .dev-badge {{
            position: absolute;
            top: 1rem;
            right: 1rem;
            background: rgba(255,0,200,0.2);
            color: var(--secondary);
            padding: 4px 10px;
            border-radius: 20px;
            font-size: 0.8rem;
            font-weight: bold;
        }}
        footer {{
            text-align: center;
            margin-top: 3rem;
            opacity: 0.6;
            font-size: 0.9rem;
        }}
        @media (max-width: 600px) {{
            body {{ padding: 1rem; }}
            .card {{ padding: 1.2rem; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🌀 NexusVault</h1>
            <p class="subtitle">Secure • Cross-Platform • Ahmed Noor Ahmed</p>
            <div class="dev-badge">v1.0.0 | Qena, Egypt</div>
        </header>

        <div class="card">
            <div class="upload-area" id="drop-area">
                <i>📁</i>
                <h3>Drag & Drop Files Here</h3>
                <p>or click to browse • Max: {config['max_file_size_mb']} MB</p>
                <input type="file" id="file-input" multiple />
                <button class="btn" id="browse-btn">📁 Select Files</button>
            </div>
            <div class="progress"><div class="progress-bar" id="progress-bar"></div></div>
            <div id="status"></div>
        </div>

        <div class="card">
            <h2>📁 Uploaded Files ({upload_log.__len__()})</h2>
            <button class="btn" onclick="location.reload()" style="margin-top:10px">🔄 Refresh</button>
            <div style="overflow-x:auto; margin-top:1rem;">
                <table id="file-list">
                    <thead>
                        <tr>
                            <th>File</th>
                            <th>Size</th>
                            <th>Date</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody id="file-table-body">
                        <!-- populated by JS -->
                    </tbody>
                </table>
            </div>
        </div>

        <footer>
            <p>NexusVault © 2025 • Developed by <strong>Ahmed Noor Ahmed</strong> • Telecommunications Engineer</p>
        </footer>
    </div>

    <script>
        const dropArea = document.getElementById('drop-area');
        const fileInput = document.getElementById('file-input');
        const browseBtn = document.getElementById('browse-btn');
        const progressBar = document.getElementById('progress-bar');
        const statusDiv = document.getElementById('status');
        const tableBody = document.getElementById('file-table-body');

        browseBtn.onclick = () => fileInput.click();
        dropArea.onclick = () => fileInput.click();

        ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {{
            dropArea.addEventListener(eventName, preventDefaults, false);
        }});

        function preventDefaults(e) {{
            e.preventDefault();
            e.stopPropagation();
        }}

        ['dragenter', 'dragover'].forEach(eventName => {{
            dropArea.addEventListener(eventName, highlight, false);
        }});

        ['dragleave', 'drop'].forEach(eventName => {{
            dropArea.addEventListener(eventName, unhighlight, false);
        }});

        function highlight() {{
            dropArea.style.borderColor = 'var(--secondary)';
            dropArea.style.backgroundColor = 'rgba(255,0,200,0.1)';
        }}

        function unhighlight() {{
            dropArea.style.borderColor = 'var(--primary)';
            dropArea.style.backgroundColor = '';
        }}

        dropArea.addEventListener('drop', handleDrop, false);
        fileInput.addEventListener('change', handleFiles, false);

        function handleDrop(e) {{
            const dt = e.dataTransfer;
            const files = dt.files;
            uploadFiles(files);
        }}

        function handleFiles() {{
            uploadFiles(this.files);
        }}

        function formatBytes(bytes) {{
            if (bytes === 0) return '0 Bytes';
            const k = 1024;
            const sizes = ['Bytes', 'KB', 'MB', 'GB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
        }}

        function uploadFiles(files) {{
            if (files.length === 0) return;
            statusDiv.innerHTML = `<p>Uploading ${files.length} file(s)...</p>`;
            progressBar.style.width = '0%';

            const uploadPromises = [];
            for (let i = 0; i < files.length; i++) {{
                const file = files[i];
                const formData = new FormData();
                formData.append('file', file);

                const xhr = new XMLHttpRequest();
                xhr.open('POST', '/upload', true);

                xhr.upload.onprogress = (e) => {{
                    if (e.lengthComputable) {{
                        const percent = (e.loaded / e.total) * 100;
                        progressBar.style.width = `${{percent * (i+1)/files.length}}%`;
                    }}
                }};

                uploadPromises.push(new Promise((resolve, reject) => {{
                    xhr.onload = () => {{
                        if (xhr.status === 200) {{
                            const res = JSON.parse(xhr.responseText);
                            resolve(res);
                        }} else {{
                            reject(xhr.statusText);
                        }}
                    }};
                    xhr.onerror = () => reject('Network Error');
                    xhr.send(formData);
                }}));
            }}

            Promise.all(uploadPromises)
                .then(results => {{
                    statusDiv.innerHTML = `<p style="color:var(--success)">✅ All uploaded! (${results.length})</p>`;
                    setTimeout(() => location.reload(), 1500);
                }})
                .catch(err => {{
                    statusDiv.innerHTML = `<p style="color:var(--danger)">❌ Upload failed: ${err}</p>`;
                }});
        }}

        // Load files
        fetch('/api/files')
            .then(res => res.json())
            .then(files => {{
                tableBody.innerHTML = '';
                files.forEach(file => {{
                    const row = document.createElement('tr');
                    const size = formatBytes(file.size);
                    const date = new Date(file.timestamp).toLocaleString();
                    const mimeIcon = file.mime.startsWith('image/') ? '🖼️' : file.mime.includes('zip') ? '📦' : '📄';

                    row.innerHTML = `
                        <td><span class="tag">${mimeIcon} ${file.filename}</span></td>
                        <td>${size}</td>
                        <td>${date}</td>
                        <td class="actions">
                            <a href="/files/${{encodeURIComponent(file.filename)}}" target="_blank">📥 Download</a>
                            <a href="#" onclick="deleteFile('${{file.filename}}'); return false;">🗑️ Delete</a>
                            <a href="/api/qr/${{encodeURIComponent(file.filename)}}" target="_blank">📱 QR</a>
                        </td>
                    `;
                    tableBody.appendChild(row);
                }});
            }});

        function deleteFile(filename) {{
            if (!confirm(`Delete "${filename}"?`)) return;
            fetch(`/api/files/${{encodeURIComponent(filename)}}`, {{ method: 'DELETE' }})
                .then(res => res.json())
                .then(data => {{
                    if (data.success) {{
                        alert('✅ Deleted');
                        location.reload();
                    }} else {{
                        alert('❌ ' + data.message);
                    }}
                }})
                .catch(err => alert('Error: ' + err));
        }}
    </script>
</body>
</html>
"""

def get_local_ip():
    import socket
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "127.0.0.1"

# ==============================
# GUI THREAD (PyQt6)
# ==============================
class ServerThread(QThread):
    started = pyqtSignal(str, int)
    stopped = pyqtSignal()
    log_message = pyqtSignal(str)

    def __init__(self, host, port):
        super().__init__()
        self.host = host
        self.port = port
        self.should_run = True

    def run(self):
        try:
            self.log_message.emit(f"🚀 Starting NexusVault Server on {self.host}:{self.port}...")
            config["port"] = self.port
            with open(CONFIG_FILE, 'w') as f:
                json.dump(config, f, indent=2)
            uvicorn.run(app, host=self.host, port=self.port, log_level="critical")
        except Exception as e:
            self.log_message.emit(f"❌ Server failed: {e}")
        finally:
            self.stopped.emit()

    def stop(self):
        self.should_run = False

class NexusVaultGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("NexusVault • File Nexus by Ahmed Noor Ahmed")
        self.resize(1100, 750)
        self.server_thread = None

        # Icon
        icon_path = BASE_DIR / "NexusVault.png"
        if icon_path.exists():
            self.setWindowIcon(QIcon(str(icon_path)))
        else:
            # Fallback icon (text-based)
            from PyQt6.QtGui import QPainter, QBrush
            pixmap = QPixmap(64, 64)
            pixmap.fill(Qt.GlobalColor.transparent)
            painter = QPainter(pixmap)
            painter.setBrush(QBrush(QColor("#00f7ff")))
            painter.drawRect(0, 0, 64, 64)
            painter.setPen(QColor("#000000"))
            painter.setFont(QFont("Arial", 24, QFont.Weight.Bold))
            painter.drawText(10, 45, "NV")
            painter.end()
            self.setWindowIcon(QIcon(pixmap))

        self.init_ui()
        self.load_config_to_ui()
        self.update_file_table()

    def init_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)

        # Title
        title_label = QLabel("🌀 NexusVault")
        title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title_label.setStyleSheet("font-size: 32px; font-weight: bold; color: #00f7ff; margin: 10px;")
        layout.addWidget(title_label)

        subtitle = QLabel("Secure • Cross-Platform • File Transfer Nexus • Developed by Ahmed Noor Ahmed, Qena")
        subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)
        subtitle.setStyleSheet("color: #aaa; font-size: 14px; margin-bottom: 20px;")
        layout.addWidget(subtitle)

        # Tabs
        tabs = QTabWidget()
        layout.addWidget(tabs)

        # === Tab 1: Server Control ===
        server_tab = QWidget()
        server_layout = QVBoxLayout(server_tab)

        # Control Group
        ctrl_group = QGroupBox("🚀 Server Control")
        ctrl_layout = QHBoxLayout()
        
        self.port_spin = QSpinBox()
        self.port_spin.setRange(1024, 65535)
        self.port_spin.setValue(8080)
        
        self.start_btn = QPushButton("🟢 Start Server")
        self.start_btn.clicked.connect(self.start_server)
        self.start_btn.setStyleSheet("font-size: 16px; padding: 10px;")
        
        self.stop_btn = QPushButton("🔴 Stop Server")
        self.stop_btn.clicked.connect(self.stop_server)
        self.stop_btn.setEnabled(False)
        self.stop_btn.setStyleSheet("font-size: 16px; padding: 10px;")

        self.open_browser_cb = QCheckBox("Auto-open browser on start")
        self.open_browser_cb.setChecked(True)

        ctrl_layout.addWidget(QLabel("Port:"))
        ctrl_layout.addWidget(self.port_spin)
        ctrl_layout.addWidget(self.start_btn)
        ctrl_layout.addWidget(self.stop_btn)
        ctrl_layout.addWidget(self.open_browser_cb)
        ctrl_group.setLayout(ctrl_layout)
        server_layout.addWidget(ctrl_group)

        # Status & Log
        self.status_label = QLabel("⏹️ Server stopped")
        self.status_label.setStyleSheet("font-size: 18px; color: #ff4d7a; font-weight: bold;")
        server_layout.addWidget(self.status_label)

        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        self.log_text.setStyleSheet("background: #111; color: #00ff88; font-family: monospace;")
        server_layout.addWidget(self.log_text)

        tabs.addTab(server_tab, "🎛️ Control")

        # === Tab 2: File Manager ===
        files_tab = QWidget()
        files_layout = QVBoxLayout(files_tab)

        # Top bar
        top_bar = QHBoxLayout()
        self.refresh_btn = QPushButton("🔄 Refresh")
        self.refresh_btn.clicked.connect(self.update_file_table)
        self.zip_selected_btn = QPushButton("📦 ZIP Selected")
        self.zip_selected_btn.clicked.connect(self.zip_selected)
        self.delete_selected_btn = QPushButton("🗑️ Delete Selected")
        self.delete_selected_btn.clicked.connect(self.delete_selected)
        top_bar.addWidget(self.refresh_btn)
        top_bar.addWidget(self.zip_selected_btn)
        top_bar.addWidget(self.delete_selected_btn)
        top_bar.addStretch()
        files_layout.addLayout(top_bar)

        # Table
        self.file_table = QTableWidget(0, 5)
        self.file_table.setHorizontalHeaderLabels(["", "Filename", "Size", "Date", "Actions"])
        self.file_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.file_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.file_table.setSortingEnabled(True)
        files_layout.addWidget(self.file_table)

        tabs.addTab(files_tab, "📁 Files")

        # === Tab 3: Settings ===
        settings_tab = QWidget()
        settings_layout = QVBoxLayout(settings_tab)

        settings_group = QGroupBox("⚙️ Advanced Settings")
        form_layout = QVBoxLayout()

        # Max size
        size_row = QHBoxLayout()
        size_row.addWidget(QLabel("Max File Size (MB):"))
        self.max_size_spin = QSpinBox()
        self.max_size_spin.setRange(1, 10000)
        self.max_size_spin.setValue(100)
        size_row.addWidget(self.max_size_spin)
        form_layout.addLayout(size_row)

        # Extensions
        ext_row = QHBoxLayout()
        ext_row.addWidget(QLabel("Allowed Extensions (comma, * = all):"))
        self.ext_edit = QLineEdit("*")
        ext_row.addWidget(self.ext_edit)
        form_layout.addLayout(ext_row)

        # Encryption (future)
        self.enc_cb = QCheckBox("Enable Upload Encryption (AES-256) — Coming Soon")
        self.enc_cb.setEnabled(False)
        form_layout.addWidget(self.enc_cb)

        # Dark mode toggle
        self.dark_cb = QCheckBox("🌙 Dark Mode (Restart to apply)")
        self.dark_cb.setChecked(True)
        form_layout.addWidget(self.dark_cb)

        settings_group.setLayout(form_layout)
        settings_layout.addWidget(settings_group)

        # Save button
        save_btn = QPushButton("💾 Save Configuration")
        save_btn.clicked.connect(self.save_config)
        save_btn.setStyleSheet("font-size: 14px; padding: 8px;")
        settings_layout.addWidget(save_btn)

        # Spacer
        settings_layout.addStretch()

        tabs.addTab(settings_tab, "⚙️ Settings")

        # === Tab 4: About ===
        about_tab = QWidget()
        about_layout = QVBoxLayout(about_tab)
        about_html = f"""
        <h2>🌀 NexusVault</h2>
        <p><b>Version:</b> 1.0.0</p>
        <p><b>Developer:</b> <span style="color:#ff00c8">Ahmed Noor Ahmed</span></p>
        <p><b>Location:</b> Qena, Egypt</p>
        <p><b>Field:</b> Telecommunications Engineer</p>
        <p><b>Description:</b> A modern, secure, cross-platform file transfer hub with GUI control, real-time management, and enterprise-grade features.</p>
        <p><b>Innovative Features:</b></p>
        <ul>
            <li>✅ SHA-256 Deduplication</li>
            <li>📱 QR Code Sharing</li>
            <li>📦 Batch ZIP Download</li>
            <li>🛡️ Path Traversal Protection</li>
            <li>📊 Real-time Upload Logging</li>
            <li>🎨 Modern Dark GUI (PyQt6)</li>
            <li>🌐 Cross-Platform (Win/Linux/macOS)</li>
        </ul>
        <p><i>© 2025 — Designed for professionals who demand reliability & style.</i></p>
        """
        about_text = QTextEdit()
        about_text.setReadOnly(True)
        about_text.setHtml(about_html)
        about_layout.addWidget(about_text)
        tabs.addTab(about_tab, "ℹ️ About")

        # Status bar
        self.statusBar().showMessage("Ready • NexusVault by Ahmed Noor Ahmed")

    def load_config_to_ui(self):
        self.port_spin.setValue(config.get("port", 8080))
        self.max_size_spin.setValue(config.get("max_file_size_mb", 100))
        self.ext_edit.setText(config.get("allowed_extensions", "*"))
        self.open_browser_cb.setChecked(config.get("auto_open_browser", True))
        self.dark_cb.setChecked(config.get("dark_mode", True))

    def save_config(self):
        config["max_file_size_mb"] = self.max_size_spin.value()
        config["allowed_extensions"] = self.ext_edit.text().strip()
        config["auto_open_browser"] = self.open_browser_cb.isChecked()
        config["dark_mode"] = self.dark_cb.isChecked()
        with open(CONFIG_FILE, 'w') as f:
            json.dump(config, f, indent=2)
        self.log("💾 Configuration saved.")

    def start_server(self):
        port = self.port_spin.value()
        host = "0.0.0.0"
        self.server_thread = ServerThread(host, port)
        self.server_thread.started.connect(self.on_server_started)
        self.server_thread.stopped.connect(self.on_server_stopped)
        self.server_thread.log_message.connect(self.log)
        self.server_thread.start()

        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.status_label.setText("▶️ Starting...")
        self.status_label.setStyleSheet("color: #ffff00;")

    def on_server_started(self, host, port):
        ip = get_local_ip()
        msg = f"✅ Server running at: http://{ip}:{port}"
        self.log(msg)
        self.status_label.setText(f"🟢 Running on {ip}:{port}")
        self.status_label.setStyleSheet("color: #00ff88;")
        if self.open_browser_cb.isChecked():
            webbrowser.open(f"http://{ip}:{port}")

    def on_server_stopped(self):
        self.log("⏹️ Server stopped.")
        self.status_label.setText("⏹️ Server stopped")
        self.status_label.setStyleSheet("color: #ff4d7a;")
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)

    def stop_server(self):
        if self.server_thread and self.server_thread.isRunning():
            self.log("🛑 Stopping server...")
            # Uvicorn doesn't support clean shutdown easily in thread — we kill thread
            self.server_thread.terminate()
            self.server_thread.wait(2000)
            if self.server_thread.isRunning():
                self.server_thread.quit()
            self.on_server_stopped()

    def log(self, msg):
        ts = datetime.now().strftime("%H:%M:%S")
        self.log_text.append(f"[{ts}] {msg}")
        self.log_text.verticalScrollBar().setValue(self.log_text.verticalScrollBar().maximum())

    def update_file_table(self):
        load_upload_log()
        self.file_table.setRowCount(len(upload_log))
        for i, file in enumerate(upload_log):
            # Checkbox
            chk = QTableWidgetItem()
            chk.setFlags(Qt.ItemFlag.ItemIsUserCheckable | Qt.ItemFlag.ItemIsEnabled)
            chk.setCheckState(Qt.CheckState.Unchecked)
            self.file_table.setItem(i, 0, chk)

            self.file_table.setItem(i, 1, QTableWidgetItem(file.get("filename", "—")))
            size = file.get("size", 0)
            size_str = f"{size / 1024:.1f} KB" if size < 1024*1024 else f"{size / (1024*1024):.1f} MB"
            self.file_table.setItem(i, 2, QTableWidgetItem(size_str))
            ts = file.get("timestamp", "")
            try:
                dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                date_str = dt.strftime("%Y-%m-%d %H:%M")
            except:
                date_str = ts[:16]
            self.file_table.setItem(i, 3, QTableWidgetItem(date_str))

            # Actions
            actions = QWidget()
            actions_layout = QHBoxLayout(actions)
            actions_layout.setContentsMargins(2, 2, 2, 2)

            btn_download = QPushButton("📥")
            btn_download.setFixedSize(30, 30)
            btn_download.clicked.connect(lambda _, f=file["filename"]: self.download_file(f))
            btn_delete = QPushButton("🗑️")
            btn_delete.setFixedSize(30, 30)
            btn_delete.clicked.connect(lambda _, f=file["filename"]: self.confirm_delete(f))
            btn_qr = QPushButton("📱")
            btn_qr.setFixedSize(30, 30)
            btn_qr.clicked.connect(lambda _, f=file["filename"]: self.show_qr(f))

            actions_layout.addWidget(btn_download)
            actions_layout.addWidget(btn_delete)
            actions_layout.addWidget(btn_qr)
            actions_layout.addStretch()

            self.file_table.setCellWidget(i, 4, actions)

    def download_file(self, filename):
        url = f"http://{get_local_ip()}:{config['port']}/files/{quote(filename)}"
        QDesktopServices.openUrl(QUrl(url))

    def show_qr(self, filename):
        url = f"http://{get_local_ip()}:{config['port']}/api/qr/{quote(filename)}"
        webbrowser.open(url)

    def confirm_delete(self, filename):
        reply = QMessageBox.question(
            self, "Confirm Delete",
            f"Are you sure you want to delete:\n<b>{filename}</b>?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        if reply == QMessageBox.StandardButton.Yes:
            self.delete_file(filename)

    def delete_file(self, filename):
        try:
            import requests
            url = f"http://127.0.0.1:{config['port']}/api/files/{quote(filename)}"
            res = requests.delete(url, timeout=3)
            if res.status_code == 200:
                self.log(f"🗑️ Deleted: {filename}")
                self.update_file_table()
            else:
                raise Exception(res.text)
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to delete:\n{e}")

    def get_selected_files(self):
        files = []
        for i in range(self.file_table.rowCount()):
            item = self.file_table.item(i, 0)
            if item and item.checkState() == Qt.CheckState.Checked:
                filename = self.file_table.item(i, 1).text()
                files.append(filename)
        return files

    def zip_selected(self):
        files = self.get_selected_files()
        if not files:
            QMessageBox.warning(self, "No Selection", "Please select files to ZIP.")
            return
        try:
            url = f"http://127.0.0.1:{config['port']}/api/download/zip?filenames={','.join(quote(f) for f in files)}"
            webbrowser.open(url)
            self.log(f"📦 ZIP requested for {len(files)} files.")
        except Exception as e:
            QMessageBox.critical(self, "ZIP Error", str(e))

    def delete_selected(self):
        files = self.get_selected_files()
        if not files:
            QMessageBox.warning(self, "No Selection", "Please select files to delete.")
            return
        reply = QMessageBox.question(
            self, "Delete Selected",
            f"Delete {len(files)} file(s)?\n{', '.join(files[:3])}{'...' if len(files)>3 else ''}",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        if reply == QMessageBox.StandardButton.Yes:
            for f in files:
                self.delete_file(f)

    def closeEvent(self, event):
        self.stop_server()
        event.accept()

# ==============================
# MAIN ENTRY
# ==============================
def main():
    app = QApplication(sys.argv)

    # Dark theme palette
    if config.get("dark_mode", True):
        dark_palette = QPalette()
        dark_palette.setColor(QPalette.ColorRole.Window, QColor(30, 30, 46))
        dark_palette.setColor(QPalette.ColorRole.WindowText, QColor(220, 220, 255))
        dark_palette.setColor(QPalette.ColorRole.Base, QColor(18, 18, 32))
        dark_palette.setColor(QPalette.ColorRole.AlternateBase, QColor(30, 30, 46))
        dark_palette.setColor(QPalette.ColorRole.ToolTipBase, QColor(255, 255, 255))
        dark_palette.setColor(QPalette.ColorRole.ToolTipText, QColor(255, 255, 255))
        dark_palette.setColor(QPalette.ColorRole.Text, QColor(220, 220, 255))
        dark_palette.setColor(QPalette.ColorRole.Button, QColor(50, 50, 80))
        dark_palette.setColor(QPalette.ColorRole.ButtonText, QColor(220, 220, 255))
        dark_palette.setColor(QPalette.ColorRole.BrightText, QColor(255, 0, 0))
        dark_palette.setColor(QPalette.ColorRole.Highlight, QColor(0, 247, 255))
        dark_palette.setColor(QPalette.ColorRole.HighlightedText, QColor(0, 0, 0))
        app.setPalette(dark_palette)
        app.setStyleSheet("QToolTip { color: #ffffff; background-color: #2a2a3e; border: 1px solid #00f7ff; }")

    gui = NexusVaultGUI()
    gui.show()

    # Auto-start if config says so (e.g., CLI arg --start)
    if "--start" in sys.argv:
        QTimer.singleShot(500, gui.start_server)

    sys.exit(app.exec())

if __name__ == "__main__":
    # Ensure uploads dir
    UPLOADS_DIR.mkdir(exist_ok=True)
    print(f"📁 Uploads directory: {UPLOADS_DIR}")
    print(f"⚙️  Config file: {CONFIG_FILE}")
    print(f"🚀 NexusVault by Ahmed Noor Ahmed — Ready.")
    main()
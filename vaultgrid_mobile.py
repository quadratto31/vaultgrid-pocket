import os
import re
import time
import hmac
import json
import html
import hashlib
import secrets
import mimetypes
import urllib.request
import urllib.parse
from datetime import datetime, timezone, timedelta
from fastapi import FastAPI, Form, UploadFile, File, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response
from supabase import create_client, Client
from huggingface_hub import HfApi

app = FastAPI(title="VaultGrid Pocket PWA", version="1.0-MOBILE")

APP_VERSION = "1.0-PWA"
SUPABASE_URL = os.environ.get("SUPABASE_URL")
SUPABASE_KEY = os.environ.get("SUPABASE_KEY")
HF_TOKEN = os.environ.get("HF_TOKEN")
HF_REPO_ID = os.environ.get("HF_REPO_ID")
WEBHOOK_URL = os.environ.get("WEBHOOK_URL", "")

supabase: Client | None = create_client(SUPABASE_URL, SUPABASE_KEY) if (SUPABASE_URL and SUPABASE_KEY) else None
hf_api = HfApi(token=HF_TOKEN) if HF_TOKEN else None

VIDEO_EXTENSIONS = {"mp4", "mov", "avi", "webm", "mkv"}
AUDIO_EXTENSIONS = {"mp3", "wav", "flac", "ogg", "m4a"}
IMAGE_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "webp", "svg", "heic"}
TEXT_EXTENSIONS = {"txt", "md", "py", "html", "css", "js", "json", "csv", "xml", "yml", "yaml", "log"}

SYSTEM_PROVIDERS = {
    "vault_chat",
    "system_lock",
    "vault_ota_module",
    "vault_note_item",
    "vault_pool",
    "vault_quota",
    "vault_audit",
    "vault_backup_profile",
    "vault_backup_snapshot",
    "vault_drop",
    "vault_rule",
    "vault_api_token",
    "vault_watch_progress",
    "vault_file_tag",
    "vault_leecher_log",
}

# --- VAULTCRYPT AES-256 KOMPATIBILNÍ ŠIFROVÁNÍ ---
def _derive_keys(password: str, salt: bytes) -> tuple[bytes, bytes]:
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 100_000, dklen=64)
    return dk[:32], dk[32:]

def _keystream_xor(data: bytes, enc_key: bytes, nonce: bytes) -> bytes:
    out = bytearray(len(data))
    counter = 0
    pos = 0
    total = len(data)
    while pos < total:
        block = hashlib.sha256(enc_key + nonce + counter.to_bytes(8, "big")).digest()
        chunk_len = min(32, total - pos)
        for i in range(chunk_len):
            out[pos + i] = data[pos + i] ^ block[i]
        pos += chunk_len
        counter += 1
    return bytes(out)

def vaultcrypt_encrypt(raw_data: bytes, password: str) -> bytes:
    magic = b"VGCRYPT1"
    salt = secrets.token_bytes(16)
    nonce = secrets.token_bytes(16)
    enc_key, mac_key = _derive_keys(password, salt)
    ciphertext = _keystream_xor(raw_data, enc_key, nonce)
    tag = hmac.new(mac_key, magic + salt + nonce + ciphertext, hashlib.sha256).digest()
    return magic + salt + nonce + tag + ciphertext

def vaultcrypt_decrypt(blob: bytes, password: str) -> bytes:
    if len(blob) < 72 or not blob.startswith(b"VGCRYPT1"):
        raise ValueError("Neplatný formát zašifrovaného souboru VaultCrypt.")
    magic = blob[:8]
    salt = blob[8:24]
    nonce = blob[24:40]
    tag = blob[40:72]
    ciphertext = blob[72:]
    enc_key, mac_key = _derive_keys(password, salt)
    expected_tag = hmac.new(mac_key, magic + salt + nonce + ciphertext, hashlib.sha256).digest()
    if not hmac.compare_digest(tag, expected_tag):
        raise ValueError("Chybné dešifrovací heslo nebo poškozená data.")
    return _keystream_xor(ciphertext, enc_key, nonce)

# --- POMOCNÉ SYSTÉMOVÉ FUNKCE (SDÍLENÉ S HLAVNÍM VAULTGRID OS) ---
def is_system_record(item: dict) -> bool:
    fname = item.get("filename", "")
    provider = item.get("storage_provider", "")
    return (
        provider in SYSTEM_PROVIDERS
        or fname.startswith(".slozkové_meta_")
        or fname.startswith(".vault_")
    )

def verify_user(username: str, password: str) -> dict | None:
    if not (supabase and username and password):
        return None
    try:
        res = supabase.table("nxt_users").select("*").eq("username", username).execute()
        if res.data and res.data[0].get("password") == password:
            return res.data[0]
    except Exception:
        pass
    return None

def log_audit(actor: str, action: str, detail: str, level: str = "INFO"):
    if not supabase:
        return
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    payload = json.dumps({
        "ts": ts,
        "actor": actor,
        "action": action,
        "detail": detail,
        "level": level
    }, ensure_ascii=False)
    try:
        supabase.table("nxt_files").insert({
            "owner": actor,
            "filename": "audit_event",
            "storage_provider": "vault_audit",
            "file_url": payload,
            "folder": "/_audit",
            "size": 0,
            "is_deleted": False
        }).execute()
    except Exception:
        pass

def get_storage_pools() -> list[dict]:
    pools = []
    if HF_REPO_ID:
        pools.append({
            "id": "pool-primary",
            "repo_id": HF_REPO_ID,
            "label": "Primary Cloud Pool (HF-01)",
            "quota_gb": 300,
            "is_active_write": True
        })
    if supabase:
        try:
            res = supabase.table("nxt_files").select("*").eq("storage_provider", "vault_pool").eq("is_deleted", False).execute()
            for row in (res.data or []):
                try:
                    data = json.loads(row.get("file_url", "{}"))
                    if data.get("repo_id"):
                        pools.append(data)
                except Exception:
                    pass
        except Exception:
            pass
    return pools

def get_active_write_repo(active_files: list[dict] | None = None) -> str:
    pools = get_storage_pools()
    if not pools:
        return HF_REPO_ID or ""
    ordered = sorted(pools, key=lambda x: 0 if x.get("is_active_write") else 1)
    for p in ordered:
        repo = p["repo_id"]
        cap_bytes = int(p.get("quota_gb", 300)) * (1024 ** 3)
        used_bytes = sum(int(f.get("size", 0)) for f in (active_files or []) if repo in f.get("file_url", ""))
        if used_bytes < (cap_bytes * 0.90):
            return repo
    return ordered[0]["repo_id"]

def get_user_quota_bytes(target_user: str) -> int:
    if not supabase:
        return 0
    try:
        res = supabase.table("nxt_files").select("*").eq("owner", target_user).eq("storage_provider", "vault_quota").eq("is_deleted", False).execute()
        if res.data:
            return int(res.data[-1].get("size", 0))
    except Exception:
        pass
    return 0

def attach_file_tag(owner: str, file_id: int, tag: str):
    clean_tag = re.sub(r"[^a-zA-Z0-9áčďéěíňóřšťúůýžÁČĎÉĚÍŇÓŘŠŤÚŮÝŽ_-]", "", tag.strip().lstrip("#")).lower()
    if not (clean_tag and supabase):
        return
    supabase.table("nxt_files").insert({
        "owner": owner,
        "filename": clean_tag,
        "storage_provider": "vault_file_tag",
        "file_url": str(file_id),
        "folder": "/_tags",
        "size": file_id,
        "is_deleted": False
    }).execute()

def apply_vault_rules(owner: str, filename: str, current_folder: str) -> tuple[str, list[str]]:
    if not supabase:
        return current_folder, []
    res = supabase.table("nxt_files").select("*").eq("owner", owner).eq("storage_provider", "vault_rule").eq("is_deleted", False).execute()
    ext = filename.split(".")[-1].lower() if "." in filename else ""
    dest_folder = current_folder
    tags_to_add: list[str] = []
    for r in (res.data or []):
        try:
            rule = json.loads(r.get("file_url", "{}"))
            r_ext = rule.get("ext", "").lower()
            r_src = rule.get("src_folder", "")
            if r_ext and r_ext != ext:
                continue
            if r_src and r_src != current_folder:
                continue
            if rule.get("dest_folder"):
                dest_folder = rule["dest_folder"]
            if rule.get("add_tag"):
                tags_to_add.append(rule["add_tag"])
        except Exception:
            pass
    return dest_folder, tags_to_add

# --- PWA MANIFEST, IKONY & SERVICE WORKER ---
ICON_SVG = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512">
  <defs>
    <linearGradient id="bg" x1="0" y1="0" x2="1" y2="1">
      <stop offset="0%" stop-color="#0f172a"/>
      <stop offset="100%" stop-color="#1d4ed8"/>
    </linearGradient>
  </defs>
  <rect width="512" height="512" rx="112" fill="url(#bg)"/>
  <rect x="112" y="128" width="288" height="104" rx="24" fill="none" stroke="#ffffff" stroke-width="26"/>
  <rect x="112" y="280" width="288" height="104" rx="24" fill="none" stroke="#60a5fa" stroke-width="26"/>
  <circle cx="168" cy="180" r="16" fill="#34d399"/>
  <circle cx="168" cy="332" r="16" fill="#60a5fa"/>
</svg>"""

@app.get("/icon.svg")
def pwa_icon_svg():
    return Response(content=ICON_SVG, media_type="image/svg+xml", headers={"Cache-Control": "public, max-age=86400"})

@app.get("/manifest.webmanifest")
def pwa_manifest():
    manifest = {
        "name": "VaultGrid Pocket",
        "short_name": "VaultGrid",
        "description": "Osobní mobilní cloudový trezor, galerie a offline úložiště.",
        "start_url": "/?source=pwa",
        "scope": "/",
        "display": "standalone",
        "orientation": "portrait",
        "background_color": "#090b0e",
        "theme_color": "#090b0e",
        "icons": [
            {"src": "/icon.svg", "sizes": "192x192", "type": "image/svg+xml", "purpose": "any maskable"},
            {"src": "/icon.svg", "sizes": "512x512", "type": "image/svg+xml", "purpose": "any maskable"},
        ],
        "shortcuts": [
            {
                "name": "Vyfotit do cloudu",
                "short_name": "Fotoaparát",
                "url": "/?action=camera",
                "icons": [{"src": "/icon.svg", "sizes": "192x192"}]
            },
            {
                "name": "Offline trezor",
                "short_name": "Offline",
                "url": "/?tab=offline",
                "icons": [{"src": "/icon.svg", "sizes": "192x192"}]
            }
        ],
        "share_target": {
            "action": "/share-target",
            "method": "POST",
            "enctype": "multipart/form-data",
            "params": {
                "title": "title",
                "text": "text",
                "url": "url",
                "files": [
                    {
                        "name": "media",
                        "accept": ["image/*", "video/*", "audio/*", "application/pdf", "*/*"]
                    }
                ]
            }
        }
    }
    return Response(content=json.dumps(manifest, ensure_ascii=False), media_type="application/manifest+json")

SW_JS = """
const CACHE_NAME = 'vaultgrid-pocket-v1';
const APP_SHELL = ['/', '/manifest.webmanifest', '/icon.svg'];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => cache.addAll(APP_SHELL))
  );
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(keys.filter((k) => k !== CACHE_NAME).map((k) => caches.delete(k)))
    )
  );
  self.clients.claim();
});

// Zachycení sdílení z galerie telefonu (Android / Chrome Web Share Target)
self.addEventListener('fetch', (event) => {
  const url = new URL(event.request.url);

  if (event.request.method === 'POST' && url.pathname === '/share-target') {
    event.respondWith((async () => {
      try {
        const formData = await event.request.formData();
        const files = formData.getAll('media');
        const sharedText = formData.get('text') || formData.get('url') || formData.get('title') || '';

        const db = await new Promise((resolve, reject) => {
          const req = indexedDB.open('vg_share_queue', 1);
          req.onupgradeneeded = () => req.result.createObjectStore('queue', { autoIncrement: true });
          req.onsuccess = () => resolve(req.result);
          req.onerror = () => reject(req.error);
        });

        const tx = db.transaction('queue', 'readwrite');
        const store = tx.objectStore('queue');
        for (const f of files) {
          if (f && f.size > 0) {
            store.add({ name: f.name || ('shared_' + Date.now()), type: f.type, file: f });
          }
        }
        if (sharedText && files.length === 0) {
          const blob = new Blob([String(sharedText)], { type: 'text/plain' });
          store.add({ name: 'sdileny_odkaz_' + Date.now() + '.txt', type: 'text/plain', file: blob });
        }
        await new Promise((res) => { tx.oncomplete = res; });
        return Response.redirect('/?shared=1', 303);
      } catch (err) {
        return Response.redirect('/?shared_err=1', 303);
      }
    })());
    return;
  }

  if (event.request.method !== 'GET') return;

  // API požadavky jdou vždy přes síť
  if (url.pathname.startsWith('/api/')) return;

  event.respondWith(
    fetch(event.request)
      .then((response) => {
        if (response && response.status === 200 && url.origin === location.origin) {
          const clone = response.clone();
          caches.open(CACHE_NAME).then((cache) => cache.put(event.request, clone));
        }
        return response;
      })
      .catch(() => caches.match(event.request).then((cached) => cached || caches.match('/')))
  );
});
"""

@app.get("/sw.js")
def pwa_service_worker():
    return Response(
        content=SW_JS,
        media_type="application/javascript",
        headers={"Service-Worker-Allowed": "/", "Cache-Control": "no-cache"},
    )

@app.post("/share-target", response_class=HTMLResponse)
async def fallback_share_target(media: list[UploadFile] = File(default=[]), text: str = Form(""), url: str = Form("")):
    # Záložní obsluha, pokud prohlížeč neprohnal POST přes Service Worker
    return HTMLResponse("""<!DOCTYPE html><html><head><meta charset="UTF-8"><meta http-equiv="refresh" content="0;url=/?shared=1"></head><body>Přesměrování do VaultGrid Pocket...</body></html>""")

# --- MOBILNÍ JSON API PRO OKAMŽITOU ODEZVU BEZ ZNOVUNAČÍTÁNÍ STRÁNKY ---
@app.post("/api/mobile/bootstrap")
def api_mobile_bootstrap(username: str = Form(...), password: str = Form(...)):
    user = verify_user(username, password)
    if not user:
        return JSONResponse({"ok": False, "error": "Neplatné přihlašovací údaje."}, status_code=401)

    rows = supabase.table("nxt_files").select("*").eq("owner", username).eq("is_deleted", False).execute().data or []
    files = []
    folders = set(["/", "/Camera", "/Downloads", "/Dokumenty", "/Notes"])
    tags_map: dict[int, list[str]] = {}

    for r in rows:
        if r.get("storage_provider") == "vault_file_tag":
            fid = int(r.get("size", 0))
            if fid and r.get("filename"):
                tags_map.setdefault(fid, []).append(r["filename"])
            continue
        if r.get("storage_provider") in SYSTEM_PROVIDERS:
            continue
        fld = r.get("folder", "/")
        if fld:
            folders.add(fld)
            # Přidání nadřazených složek do stromu
            parts = fld.strip("/").split("/")
            acc = ""
            for p in parts:
                if p:
                    acc += "/" + p
                    folders.add(acc)
        if not is_system_record(r):
            ext = r["filename"].split(".")[-1].lower() if "." in r["filename"] else ""
            ftype = "file"
            if ext in IMAGE_EXTENSIONS:
                ftype = "image"
            elif ext in VIDEO_EXTENSIONS:
                ftype = "video"
            elif ext in AUDIO_EXTENSIONS:
                ftype = "audio"
            elif ext == "pdf":
                ftype = "pdf"
            elif ext in TEXT_EXTENSIONS:
                ftype = "text"
            files.append({
                "id": r["id"],
                "filename": r["filename"],
                "folder": fld,
                "size": int(r.get("size", 0)),
                "file_url": r.get("file_url", "#"),
                "ext": ext,
                "type": ftype,
                "encrypted": r["filename"].endswith(".vgenc"),
                "tags": []
            })

    for f in files:
        f["tags"] = tags_map.get(f["id"], [])

    files.sort(key=lambda x: x["id"], reverse=True)
    used_bytes = sum(f["size"] for f in files)
    quota_bytes = get_user_quota_bytes(username)

    return JSONResponse({
        "ok": True,
        "username": username,
        "role": user.get("role", "uzivatel"),
        "used_bytes": used_bytes,
        "quota_bytes": quota_bytes,
        "folders": sorted(list(folders)),
        "files": files
    })

@app.post("/api/mobile/upload")
async def api_mobile_upload(
    username: str = Form(...),
    password: str = Form(...),
    folder: str = Form("/Camera"),
    encrypt_pass: str = Form(""),
    file: UploadFile = File(...)
):
    user = verify_user(username, password)
    if not user:
        return JSONResponse({"ok": False, "error": "Neautorizováno"}, status_code=401)

    raw_bytes = await file.read()
    if not raw_bytes:
        return JSONResponse({"ok": False, "error": "Prázdný soubor"}, status_code=400)

    final_name = file.filename or f"mobile_{int(time.time())}.bin"
    final_bytes = raw_bytes
    if encrypt_pass.strip():
        final_bytes = vaultcrypt_encrypt(raw_bytes, encrypt_pass.strip())
        final_name = final_name + ".vgenc"

    clean_folder = folder.strip() or "/Camera"
    if not clean_folder.startswith("/"):
        clean_folder = "/" + clean_folder

    quota_limit = get_user_quota_bytes(username)
    all_rows = supabase.table("nxt_files").select("*").eq("is_deleted", False).execute().data or []
    active_global = [r for r in all_rows if not is_system_record(r)]
    current_used = sum(int(f.get("size", 0)) for f in active_global if f.get("owner") == username)

    if quota_limit > 0 and (current_used + len(final_bytes)) > quota_limit:
        return JSONResponse({"ok": False, "error": "Překročena disková kvóta účtu."}, status_code=413)

    routed_folder, auto_tags = apply_vault_rules(username, final_name, clean_folder)
    repo_id = get_active_write_repo(active_global)
    repo_path = f"{username}{routed_folder}/{final_name}".replace("//", "/")

    if hf_api and repo_id:
        hf_api.upload_file(path_or_fileobj=final_bytes, path_in_repo=repo_path, repo_id=repo_id, repo_type="dataset")
        public_url = f"https://huggingface.co/datasets/{repo_id}/resolve/main/{repo_path}"
    else:
        public_url = "#"

    ins = supabase.table("nxt_files").insert({
        "owner": username,
        "filename": final_name,
        "storage_provider": "huggingface",
        "file_url": public_url,
        "folder": routed_folder,
        "size": len(final_bytes),
        "is_deleted": False
    }).execute()

    if ins.data and auto_tags:
        for t in auto_tags:
            attach_file_tag(username, ins.data[0]["id"], t)

    log_audit(username, "MOBILE_PWA_UPLOAD", f"Nahráno z mobilu: {routed_folder}/{final_name}", "INFO")
    return JSONResponse({"ok": True, "filename": final_name, "folder": routed_folder})

@app.post("/api/mobile/create-folder")
def api_mobile_create_folder(username: str = Form(...), password: str = Form(...), parent_folder: str = Form("/"), name: str = Form(...)):
    user = verify_user(username, password)
    if not user:
        return JSONResponse({"ok": False, "error": "Neautorizováno"}, status_code=401)
    clean_name = name.strip().replace("/", "")
    if not clean_name:
        return JSONResponse({"ok": False, "error": "Prázdný název"}, status_code=400)
    new_path = f"{parent_folder.rstrip('/')}/{clean_name}"
    supabase.table("nxt_files").insert({
        "owner": username,
        "filename": f".slozkové_meta_{clean_name}",
        "storage_provider": "system",
        "file_url": "#",
        "folder": new_path,
        "size": 0,
        "is_deleted": False
    }).execute()
    return JSONResponse({"ok": True, "folder": new_path})

@app.post("/api/mobile/delete")
def api_mobile_delete(username: str = Form(...), password: str = Form(...), file_id: int = Form(...)):
    user = verify_user(username, password)
    if not user:
        return JSONResponse({"ok": False, "error": "Neautorizováno"}, status_code=401)
    supabase.table("nxt_files").update({"is_deleted": True}).eq("id", file_id).eq("owner", username).execute()
    return JSONResponse({"ok": True})

@app.post("/api/mobile/quick-note")
def api_mobile_quick_note(username: str = Form(...), password: str = Form(...), title: str = Form(""), content: str = Form(...)):
    user = verify_user(username, password)
    if not user:
        return JSONResponse({"ok": False, "error": "Neautorizováno"}, status_code=401)
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    safe_title = re.sub(r"[^a-zA-Z0-9áčďéěíňóřšťúůýžÁČĎÉĚÍŇÓŘŠŤÚŮÝŽ_-]", "_", title.strip()) or f"poznamka_{ts}"
    fname = f"{safe_title}.md"
    raw = f"# {title.strip() or 'Mobilní poznámka'}\n\n{content.strip()}\n".encode("utf-8")
    repo_id = get_active_write_repo()
    repo_path = f"{username}/Notes/{fname}"
    if hf_api and repo_id:
        hf_api.upload_file(path_or_fileobj=raw, path_in_repo=repo_path, repo_id=repo_id, repo_type="dataset")
        purl = f"https://huggingface.co/datasets/{repo_id}/resolve/main/{repo_path}"
    else:
        purl = "#"
    supabase.table("nxt_files").insert({
        "owner": username,
        "filename": fname,
        "storage_provider": "huggingface",
        "file_url": purl,
        "folder": "/Notes",
        "size": len(raw),
        "is_deleted": False
    }).execute()
    return JSONResponse({"ok": True, "filename": fname})

@app.post("/api/mobile/vaultdrop")
def api_mobile_vaultdrop(request: Request, username: str = Form(...), password: str = Form(...), file_id: int = Form(...), expire_hours: int = Form(24)):
    user = verify_user(username, password)
    if not user:
        return JSONResponse({"ok": False, "error": "Neautorizováno"}, status_code=401)
    rec = (supabase.table("nxt_files").select("*").eq("id", file_id).eq("owner", username).execute().data or [None])[0]
    if not rec:
        return JSONResponse({"ok": False, "error": "Soubor nenalezen"}, status_code=404)
    token = secrets.token_urlsafe(12)
    exp_str = (datetime.now(timezone.utc) + timedelta(hours=expire_hours)).strftime("%Y-%m-%d %H:%M UTC") if expire_hours > 0 else ""
    meta = json.dumps({
        "type": "download",
        "token": token,
        "file_id": file_id,
        "label": rec["filename"],
        "expires_at": exp_str,
        "max_downloads": 0,
        "downloads_used": 0,
        "password": ""
    }, ensure_ascii=False)
    supabase.table("nxt_files").insert({
        "owner": username,
        "filename": token,
        "storage_provider": "vault_drop",
        "file_url": meta,
        "folder": "/_drops",
        "size": 0,
        "is_deleted": False
    }).execute()
    base = str(request.base_url).rstrip("/")
    if "onrender.com" in base and base.startswith("http://"):
        base = "https://" + base[len("http://"):]
    return JSONResponse({"ok": True, "share_url": f"{base}/drop/{token}", "filename": rec["filename"]})

@app.get("/drop/{token}", response_class=HTMLResponse)
def mobile_public_drop(token: str):
    if not supabase:
        return HTMLResponse("Offline", status_code=503)
    res = supabase.table("nxt_files").select("*").eq("storage_provider", "vault_drop").eq("filename", token).execute()
    if not res.data:
        return HTMLResponse("Odkaz neexistuje.", status_code=404)
    meta = json.loads(res.data[0].get("file_url", "{}"))
    f_rec = (supabase.table("nxt_files").select("*").eq("id", meta.get("file_id")).execute().data or [None])[0]
    if not f_rec:
        return HTMLResponse("Soubor nenalezen.", status_code=404)
    return HTMLResponse(f"""<!DOCTYPE html><html lang="cs"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
    <title>{html.escape(f_rec['filename'])}</title>
    <style>body{{margin:0;background:#090b0e;color:#f3f4f6;font-family:-apple-system,sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;padding:20px;}}
    .card{{background:#131720;border:1px solid #262d3d;border-radius:20px;padding:28px;max-width:400px;width:100%;text-align:center;}}
    .btn{{display:block;background:#2563eb;color:#fff;text-decoration:none;padding:15px;border-radius:14px;font-weight:600;margin-top:18px;}}</style></head>
    <body><div class="card"><h2>VaultDrop Přenos</h2><p>{html.escape(f_rec['filename'])}</p>
    <a href="{html.escape(f_rec['file_url'])}" download class="btn">Stáhnout soubor</a></div></body></html>""")

@app.post("/api/mobile/decrypt")
def api_mobile_decrypt(username: str = Form(...), password: str = Form(...), file_id: int = Form(...), decrypt_pass: str = Form(...)):
    user = verify_user(username, password)
    if not user:
        return Response("Unauthorized", status_code=401)
    rec = (supabase.table("nxt_files").select("*").eq("id", file_id).eq("owner", username).execute().data or [None])[0]
    if not rec:
        return Response("Not found", status_code=404)
    try:
        with urllib.request.urlopen(rec["file_url"], timeout=12) as resp:
            enc_bytes = resp.read()
        plain = vaultcrypt_decrypt(enc_bytes, decrypt_pass.strip())
        orig_name = rec["filename"][:-6] if rec["filename"].endswith(".vgenc") else rec["filename"]
        return Response(
            content=plain,
            media_type="application/octet-stream",
            headers={"Content-Disposition": f'attachment; filename="{orig_name}"'}
        )
    except Exception as e:
        return Response(str(e), status_code=400)

# --- HLAVNÍ MOBILNÍ PWA APLIKACE (SINGLE-PAGE NATIVE MOBILE SHELL) ---
@app.get("/", response_class=HTMLResponse)
def mobile_pwa_app():
    return """<!DOCTYPE html>
<html lang="cs" data-theme="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no, viewport-fit=cover">
    <meta name="theme-color" content="#090b0e">
    <meta name="apple-mobile-web-app-capable" content="yes">
    <meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
    <meta name="apple-mobile-web-app-title" content="VaultGrid">
    <link rel="manifest" href="/manifest.webmanifest">
    <link rel="icon" href="/icon.svg" type="image/svg+xml">
    <link rel="apple-touch-icon" href="/icon.svg">
    <title>VaultGrid Pocket</title>
    <style>
        :root {
            --bg: #090b0e;
            --surface: #131720;
            --surface-2: #1b212e;
            --border: #262e3f;
            --text: #f3f4f6;
            --muted: #9ca3af;
            --accent: #3b82f6;
            --accent-bg: rgba(59, 130, 246, 0.14);
            --success: #10b981;
            --warning: #f59e0b;
            --danger: #ef4444;
            --safe-top: env(safe-area-inset-top, 0px);
            --safe-bottom: env(safe-area-inset-bottom, 0px);
        }
        html[data-theme="light"] {
            --bg: #f3f4f6;
            --surface: #ffffff;
            --surface-2: #f9fafb;
            --border: #e5e7eb;
            --text: #111827;
            --muted: #6b7280;
            --accent: #2563eb;
            --accent-bg: rgba(37, 99, 235, 0.10);
        }
        * { box-sizing: border-box; -webkit-tap-highlight-color: transparent; }
        body {
            margin: 0;
            background: var(--bg);
            color: var(--text);
            font-family: -apple-system, BlinkMacSystemFont, 'SF Pro Display', 'Segoe UI', Roboto, sans-serif;
            font-size: 15px;
            line-height: 1.45;
            overscroll-behavior-y: contain;
            padding-top: calc(58px + var(--safe-top));
            padding-bottom: calc(82px + var(--safe-bottom));
        }

        /* TOP APP BAR */
        .app-header {
            position: fixed;
            top: 0; left: 0; right: 0;
            height: calc(58px + var(--safe-top));
            padding: var(--safe-top) 16px 0 16px;
            background: rgba(9, 11, 14, 0.86);
            backdrop-filter: blur(18px);
            -webkit-backdrop-filter: blur(18px);
            border-bottom: 1px solid var(--border);
            display: flex;
            align-items: center;
            justify-content: space-between;
            z-index: 40;
        }
        html[data-theme="light"] .app-header { background: rgba(255, 255, 255, 0.88); }
        .header-title { font-size: 17px; font-weight: 700; display: flex; align-items: center; gap: 8px; }
        .status-dot { width: 8px; height: 8px; border-radius: 50%; background: var(--success); display: inline-block; }
        .status-dot.offline { background: var(--warning); }

        /* BOTTOM TAB BAR (THUMB ZONE) */
        .tab-bar {
            position: fixed;
            bottom: 0; left: 0; right: 0;
            height: calc(68px + var(--safe-bottom));
            padding-bottom: var(--safe-bottom);
            background: rgba(19, 23, 32, 0.92);
            backdrop-filter: blur(20px);
            -webkit-backdrop-filter: blur(20px);
            border-top: 1px solid var(--border);
            display: grid;
            grid-template-columns: repeat(5, 1fr);
            align-items: center;
            z-index: 45;
        }
        html[data-theme="light"] .tab-bar { background: rgba(255, 255, 255, 0.94); }
        .tab-btn {
            background: none;
            border: none;
            color: var(--muted);
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            gap: 4px;
            font-size: 11px;
            font-weight: 600;
            padding: 6px 0;
            cursor: pointer;
        }
        .tab-btn.active { color: var(--accent); }
        .fab-upload {
            width: 50px; height: 50px;
            border-radius: 18px;
            background: linear-gradient(135deg, #2563eb, #3b82f6);
            color: #fff;
            display: flex;
            align-items: center;
            justify-content: center;
            box-shadow: 0 6px 20px rgba(37, 99, 235, 0.45);
            margin-top: -14px;
        }

        /* CONTAINERS & CARDS */
        .page { display: none; padding: 14px 16px; max-width: 640px; margin: 0 auto; }
        .page.active { display: block; animation: fadeIn 0.16s ease; }
        @keyframes fadeIn { from { opacity: 0; transform: translateY(4px); } to { opacity: 1; transform: translateY(0); } }

        .card {
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 18px;
            padding: 16px;
            margin-bottom: 14px;
        }
        .card-title { font-size: 14px; font-weight: 700; color: var(--muted); text-transform: uppercase; letter-spacing: 0.04em; margin: 0 0 12px 0; }

        /* QUICK ACTION GRID */
        .quick-grid {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 10px;
            margin-bottom: 16px;
        }
        .quick-item {
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 16px;
            padding: 12px 6px;
            display: flex;
            flex-direction: column;
            align-items: center;
            gap: 7px;
            color: var(--text);
            font-size: 12px;
            font-weight: 600;
            cursor: pointer;
        }
        .quick-item:active { transform: scale(0.96); background: var(--surface-2); }
        .quick-icon {
            width: 40px; height: 40px;
            border-radius: 12px;
            background: var(--accent-bg);
            color: var(--accent);
            display: flex;
            align-items: center;
            justify-content: center;
        }

        /* FILE LIST ROWS (LARGE TOUCH TARGETS) */
        .file-row {
            display: flex;
            align-items: center;
            gap: 12px;
            padding: 12px;
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 15px;
            margin-bottom: 9px;
            cursor: pointer;
        }
        .file-row:active { background: var(--surface-2); }
        .file-thumb {
            width: 44px; height: 44px;
            border-radius: 12px;
            background: var(--surface-2);
            display: flex;
            align-items: center;
            justify-content: center;
            flex-shrink: 0;
            overflow: hidden;
            color: var(--accent);
        }
        .file-thumb img { width: 100%; height: 100%; object-fit: cover; }
        .file-meta { flex: 1; min-width: 0; }
        .file-name { font-weight: 600; font-size: 14.5px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
        .file-sub { font-size: 12px; color: var(--muted); display: flex; gap: 6px; align-items: center; margin-top: 2px; }
        .more-btn {
            width: 38px; height: 38px;
            border-radius: 10px;
            border: none;
            background: transparent;
            color: var(--muted);
            display: flex;
            align-items: center;
            justify-content: center;
            cursor: pointer;
        }

        /* PHOTO GRID (3 COLUMNS) */
        .photo-grid {
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 4px;
            border-radius: 14px;
            overflow: hidden;
        }
        .photo-cell {
            aspect-ratio: 1 / 1;
            background: var(--surface-2);
            overflow: hidden;
            cursor: pointer;
        }
        .photo-cell img { width: 100%; height: 100%; object-fit: cover; display: block; }

        /* INPUTS & BUTTONS */
        input, select, textarea {
            width: 100%;
            padding: 13px 14px;
            border-radius: 13px;
            border: 1px solid var(--border);
            background: var(--surface-2);
            color: var(--text);
            font-size: 15px;
            font-family: inherit;
            outline: none;
        }
        input:focus, textarea:focus { border-color: var(--accent); }
        .btn {
            width: 100%;
            padding: 14px;
            border-radius: 14px;
            border: none;
            background: var(--accent);
            color: #fff;
            font-size: 15px;
            font-weight: 700;
            cursor: pointer;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            gap: 8px;
        }
        .btn:active { opacity: 0.88; transform: scale(0.99); }
        .btn-sec { background: var(--surface-2); color: var(--text); border: 1px solid var(--border); }
        .btn-danger { background: rgba(239, 68, 68, 0.15); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.35); }

        /* FOLDER CHIPS */
        .chips-row {
            display: flex;
            gap: 8px;
            overflow-x: auto;
            padding-bottom: 8px;
            margin-bottom: 10px;
            scrollbar-width: none;
        }
        .chips-row::-webkit-scrollbar { display: none; }
        .chip {
            padding: 7px 13px;
            border-radius: 20px;
            background: var(--surface);
            border: 1px solid var(--border);
            color: var(--muted);
            font-size: 13px;
            font-weight: 600;
            white-space: nowrap;
            cursor: pointer;
        }
        .chip.active { background: var(--accent); color: #fff; border-color: var(--accent); }

        /* BOTTOM SHEET MODAL */
        .sheet-backdrop {
            position: fixed;
            inset: 0;
            background: rgba(0, 0, 0, 0.65);
            z-index: 60;
            display: none;
            align-items: flex-end;
        }
        .sheet-backdrop.open { display: flex; }
        .bottom-sheet {
            width: 100%;
            max-width: 640px;
            margin: 0 auto;
            background: var(--surface);
            border-top-left-radius: 24px;
            border-top-right-radius: 24px;
            border-top: 1px solid var(--border);
            padding: 14px 18px calc(24px + var(--safe-bottom)) 18px;
            animation: slideUp 0.2s ease;
        }
        @keyframes slideUp { from { transform: translateY(100%); } to { transform: translateY(0); } }
        .sheet-handle { width: 38px; height: 4px; border-radius: 4px; background: var(--border); margin: 0 auto 14px auto; }
        .sheet-action {
            width: 100%;
            padding: 14px;
            border-radius: 13px;
            border: none;
            background: var(--surface-2);
            color: var(--text);
            font-size: 15px;
            font-weight: 600;
            text-align: left;
            margin-bottom: 8px;
            display: flex;
            align-items: center;
            gap: 12px;
            cursor: pointer;
        }

        /* FULLSCREEN PREVIEW LIGHTBOX */
        .lightbox {
            position: fixed;
            inset: 0;
            background: #000;
            z-index: 80;
            display: none;
            flex-direction: column;
            padding-top: var(--safe-top);
            padding-bottom: var(--safe-bottom);
        }
        .lightbox.open { display: flex; }
        .lb-top {
            padding: 12px 16px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            color: #fff;
            background: rgba(0,0,0,0.7);
        }
        .lb-body {
            flex: 1;
            display: flex;
            align-items: center;
            justify-content: center;
            overflow: auto;
            padding: 12px;
        }

        /* TOAST NOTIFICATION */
        .toast {
            position: fixed;
            top: calc(68px + var(--safe-top));
            left: 50%;
            transform: translateX(-50%);
            background: #1e293b;
            color: #fff;
            border: 1px solid #334155;
            padding: 10px 18px;
            border-radius: 24px;
            font-size: 13.5px;
            font-weight: 600;
            z-index: 90;
            box-shadow: 0 8px 24px rgba(0,0,0,0.4);
            display: none;
            white-space: nowrap;
        }

        /* LOGIN SCREEN */
        .login-overlay {
            position: fixed;
            inset: 0;
            background: var(--bg);
            z-index: 100;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }
    </style>
</head>
<body>

    <!-- TOAST -->
    <div id="toast" class="toast"></div>

    <!-- LOGIN OVERLAY -->
    <div id="login-screen" class="login-overlay">
        <div class="card" style="width:100%; max-width:400px; padding:26px;">
            <div style="display:flex; align-items:center; gap:12px; margin-bottom:16px;">
                <img src="/icon.svg" width="46" height="46" alt="Icon">
                <div>
                    <div style="font-size:20px; font-weight:800;">VaultGrid Pocket</div>
                    <div style="font-size:12.5px; color:var(--muted);">Mobilní Cloud & Offline Trezor</div>
                </div>
            </div>
            <p style="color:var(--muted); font-size:13.5px; margin-top:0;">Přihlas se svým účtem z VaultGrid OS. Přihlášení zůstane uložené v telefonu.</p>
            <form onsubmit="handleLogin(event)">
                <input type="text" id="login-user" placeholder="Uživatelské jméno" required autocomplete="username" style="margin-bottom:10px;">
                <input type="password" id="login-pass" placeholder="Heslo" required autocomplete="current-password" style="margin-bottom:16px;">
                <button type="submit" id="login-btn" class="btn">Přihlásit se</button>
            </form>
        </div>
    </div>

    <!-- TOP BAR -->
    <header class="app-header">
        <div class="header-title">
            <span id="net-dot" class="status-dot"></span>
            <span id="header-text">VaultGrid Pocket</span>
        </div>
        <div style="display:flex; gap:8px; align-items:center;">
            <button type="button" onclick="syncAll()" class="more-btn" title="Obnovit">
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/></svg>
            </button>
            <button type="button" onclick="toggleTheme()" class="more-btn" title="Vzhled">
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><circle cx="12" cy="12" r="5"/><line x1="12" y1="1" x2="12" y2="3"/><line x1="12" y1="21" x2="12" y2="23"/><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/></svg>
            </button>
        </div>
    </header>

    <!-- TAB 1: DOMŮ (HOME) -->
    <main id="page-home" class="page active">
        <div class="card" style="background: linear-gradient(135deg, #172554, #1e3a8a); border-color: #2563eb; color: #fff;">
            <div style="display:flex; justify-content:space-between; align-items:center;">
                <div>
                    <div style="font-size:12px; opacity:0.8; text-transform:uppercase; letter-spacing:0.05em;">Cloudové úložiště</div>
                    <div id="home-used" style="font-size:26px; font-weight:800; margin:2px 0;">0.0 MB</div>
                    <div id="home-quota" style="font-size:12.5px; opacity:0.85;">Kvóta: Bez limitu</div>
                </div>
                <div style="text-align:right;">
                    <div id="home-count" style="font-size:22px; font-weight:800;">0</div>
                    <div style="font-size:12px; opacity:0.8;">souborů</div>
                </div>
            </div>
        </div>

        <div class="quick-grid">
            <div class="quick-item" onclick="triggerCamera()">
                <div class="quick-icon"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><path d="M23 19a2 2 0 0 1-2 2H3a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h4l2-3h6l2 3h4a2 2 0 0 1 2 2z"/><circle cx="12" cy="13" r="4"/></svg></div>
                <span>Vyfotit</span>
            </div>
            <div class="quick-item" onclick="switchTab('upload')">
                <div class="quick-icon"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/></svg></div>
                <span>Nahrát</span>
            </div>
            <div class="quick-item" onclick="openNoteSheet()">
                <div class="quick-icon"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><path d="M12 20h9"/><path d="M16.5 3.5a2.121 2.121 0 0 1 3 3L7 19l-4 1 1-4L16.5 3.5z"/></svg></div>
                <span>Poznámka</span>
            </div>
            <div class="quick-item" onclick="switchTab('offline')">
                <div class="quick-icon"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg></div>
                <span>Offline</span>
            </div>
        </div>

        <div id="install-banner" class="card" style="display:none; border-color: var(--accent);">
            <div style="display:flex; justify-content:space-between; align-items:center; gap:12px;">
                <div>
                    <div style="font-weight:700;">Nainstalovat na plochu</div>
                    <div style="font-size:12.5px; color:var(--muted);">Spouštěj VaultGrid jako nativní aplikaci na celou obrazovku.</div>
                </div>
                <button type="button" onclick="installPWA()" class="btn" style="width:auto; padding:10px 16px;">Instalovat</button>
            </div>
        </div>

        <h3 class="card-title">Poslední nahrané soubory</h3>
        <div id="home-recent"></div>
    </main>

    <!-- TAB 2: SOUBORY (FILES) -->
    <main id="page-files" class="page">
        <div style="display:flex; gap:8px; margin-bottom:10px;">
            <input type="search" id="search-input" placeholder="Hledat soubor nebo #štítek..." oninput="renderFilesList()">
            <button type="button" onclick="createNewFolderPrompt()" class="btn btn-sec" style="width:auto; padding:0 14px;" title="Nová složka">+ Složka</button>
        </div>

        <div id="folder-chips" class="chips-row"></div>
        <div id="files-list"></div>
    </main>

    <!-- TAB 3: NAHRÁT (UPLOAD & CAMERA) -->
    <main id="page-upload" class="page">
        <div class="card">
            <h3 class="card-title">Nahrát z mobilu do cloudu</h3>
            <label style="font-size:13px; color:var(--muted);">Cílová složka</label>
            <select id="upload-folder" style="margin:6px 0 12px 0;">
                <option value="/Camera">/Camera (Fotky a videa)</option>
                <option value="/Downloads">/Downloads</option>
                <option value="/Dokumenty">/Dokumenty</option>
                <option value="/">/ (Kořenový adresář)</option>
            </select>

            <label style="display:flex; align-items:center; gap:10px; margin-bottom:12px; font-size:14px; cursor:pointer;">
                <input type="checkbox" id="upload-enc-chk" style="width:20px; height:20px;" onchange="document.getElementById('upload-enc-pass').style.display = this.checked ? 'block' : 'none'">
                <span>Zašifrovat v mobilu (VaultCrypt AES-256)</span>
            </label>
            <input type="password" id="upload-enc-pass" placeholder="Zadejte šifrovací heslo..." style="display:none; margin-bottom:12px;">

            <input type="file" id="picker-files" multiple style="display:none;" onchange="handleSelectedFiles(this.files)">
            <input type="file" id="picker-camera" accept="image/*,video/*" capture="environment" style="display:none;" onchange="handleSelectedFiles(this.files)">

            <div style="display:grid; grid-template-columns:1fr 1fr; gap:10px; margin-bottom:12px;">
                <button type="button" onclick="document.getElementById('picker-camera').click()" class="btn">
                    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><path d="M23 19a2 2 0 0 1-2 2H3a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h4l2-3h6l2 3h4a2 2 0 0 1 2 2z"/><circle cx="12" cy="13" r="4"/></svg>
                    Fotoaparát
                </button>
                <button type="button" onclick="document.getElementById('picker-files').click()" class="btn btn-sec">
                    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/></svg>
                    Galerie / Soubory
                </button>
            </div>

            <div id="upload-progress-box" style="display:none; padding:12px; background:var(--surface-2); border-radius:12px;">
                <div style="display:flex; justify-content:space-between; font-size:13px; margin-bottom:6px;">
                    <span id="up-status">Nahrávání...</span>
                    <span id="up-pct">0%</span>
                </div>
                <div style="height:8px; background:var(--bg); border-radius:6px; overflow:hidden;">
                    <div id="up-bar" style="height:100%; width:0%; background:var(--accent); transition:width 0.15s;"></div>
                </div>
            </div>
        </div>

        <div class="card">
            <h3 class="card-title">Tip: Sdílet přímo z Galerie telefonu</h3>
            <p style="color:var(--muted); font-size:13.5px; margin:0;">
                Po přidání aplikace na plochu otevři v telefonu <strong>Galerii</strong>, vyber libovolné fotky a klepni na <strong>Sdílet → VaultGrid</strong>. Soubory se automaticky odešlou do tvého cloudu!
            </p>
        </div>
    </main>

    <!-- TAB 4: MÉDIA (GALERIE & PŘEHRÁVAČ) -->
    <main id="page-media" class="page">
        <h3 class="card-title">Fotogalerie v cloudu</h3>
        <div id="media-photos" class="photo-grid" style="margin-bottom:18px;"></div>

        <h3 class="card-title">Videa a hudba</h3>
        <div id="media-av"></div>
    </main>

    <!-- TAB 5: OFFLINE TREZOR & ÚČET -->
    <main id="page-offline" class="page">
        <div class="card">
            <h3 class="card-title">Offline Trezor v telefonu (IndexedDB)</h3>
            <p style="color:var(--muted); font-size:13px; margin-top:0;">
                Soubory uložené zde jsou uloženy přímo v paměti telefonu a otevřeš je i v letadle nebo metru bez internetu.
            </p>
            <div id="offline-list"></div>
        </div>

        <div class="card">
            <h3 class="card-title">Instalace na iPhone (Safari)</h3>
            <p style="color:var(--muted); font-size:13px; margin:0;">
                1. Otevři tuto stránku v prohlížeči <strong>Safari</strong>.<br>
                2. Klepni na ikonu <strong>Sdílet</strong> (čtvereček se šipkou nahoru).<br>
                3. Zvol <strong>Přidat na plochu (Add to Home Screen)</strong>.
            </p>
        </div>

        <button type="button" onclick="logout()" class="btn btn-danger">Odhlásit se z tohoto zařízení</button>
    </main>

    <!-- BOTTOM TAB BAR -->
    <nav class="tab-bar">
        <button type="button" class="tab-btn active" id="nav-home" onclick="switchTab('home')">
            <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.1"><path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/></svg>
            <span>Domů</span>
        </button>
        <button type="button" class="tab-btn" id="nav-files" onclick="switchTab('files')">
            <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.1"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/></svg>
            <span>Soubory</span>
        </button>
        <button type="button" class="tab-btn" id="nav-upload" onclick="switchTab('upload')">
            <div class="fab-upload">
                <svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.6"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>
            </div>
            <span>Nahrát</span>
        </button>
        <button type="button" class="tab-btn" id="nav-media" onclick="switchTab('media')">
            <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.1"><rect x="3" y="3" width="18" height="18" rx="2"/><circle cx="8.5" cy="8.5" r="1.5"/><polyline points="21 15 16 10 5 21"/></svg>
            <span>Média</span>
        </button>
        <button type="button" class="tab-btn" id="nav-offline" onclick="switchTab('offline')">
            <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.1"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
            <span>Offline</span>
        </button>
    </nav>

    <!-- ACTION BOTTOM SHEET -->
    <div id="action-sheet" class="sheet-backdrop" onclick="if(event.target===this) closeSheet()">
        <div class="bottom-sheet">
            <div class="sheet-handle"></div>
            <div id="sheet-filename" style="font-weight:700; font-size:16px; margin-bottom:14px; word-break:break-word;"></div>
            <div id="sheet-buttons"></div>
        </div>
    </div>

    <!-- QUICK NOTE SHEET -->
    <div id="note-sheet" class="sheet-backdrop" onclick="if(event.target===this) this.classList.remove('open')">
        <div class="bottom-sheet">
            <div class="sheet-handle"></div>
            <div style="font-weight:700; font-size:16px; margin-bottom:12px;">Rychlá poznámka do cloudu</div>
            <input type="text" id="note-title" placeholder="Název poznámky..." style="margin-bottom:10px;">
            <textarea id="note-body" rows="5" placeholder="Napiš nebo nadiktuj poznámku..." style="margin-bottom:12px;"></textarea>
            <button type="button" onclick="saveQuickNote()" class="btn">Uložit do /Notes</button>
        </div>
    </div>

    <!-- FULLSCREEN LIGHTBOX -->
    <div id="lightbox" class="lightbox">
        <div class="lb-top">
            <span id="lb-title" style="font-weight:600; font-size:14px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; max-width:75%;"></span>
            <button type="button" onclick="closeLightbox()" style="background:#262e3f; color:#fff; border:none; padding:8px 14px; border-radius:10px; font-weight:700;">Zavřít</button>
        </div>
        <div id="lb-body" class="lb-body"></div>
    </div>

    <script>
        let SESSION = {
            username: localStorage.getItem('vg_mob_user') || '',
            password: localStorage.getItem('vg_mob_pass') || ''
        };
        let STATE = {
            files: [],
            folders: ['/', '/Camera', '/Downloads', '/Dokumenty', '/Notes'],
            currentFolder: 'ALL',
            usedBytes: 0,
            quotaBytes: 0
        };
        let deferredPrompt = null;

        // Registrace Service Workeru
        if ('serviceWorker' in navigator) {
            navigator.serviceWorker.register('/sw.js').catch(() => {});
        }

        window.addEventListener('beforeinstallprompt', (e) => {
            e.preventDefault();
            deferredPrompt = e;
            document.getElementById('install-banner').style.display = 'block';
        });

        async function installPWA() {
            if (!deferredPrompt) return;
            deferredPrompt.prompt();
            await deferredPrompt.userChoice;
            deferredPrompt = null;
            document.getElementById('install-banner').style.display = 'none';
        }

        function toggleTheme() {
            const cur = document.documentElement.getAttribute('data-theme') || 'dark';
            const next = cur === 'dark' ? 'light' : 'dark';
            document.documentElement.setAttribute('data-theme', next);
            localStorage.setItem('vg_mob_theme', next);
        }
        (function() {
            const t = localStorage.getItem('vg_mob_theme');
            if (t) document.documentElement.setAttribute('data-theme', t);
        })();

        function showToast(msg) {
            const el = document.getElementById('toast');
            el.innerText = msg;
            el.style.display = 'block';
            clearTimeout(window._toastTimer);
            window._toastTimer = setTimeout(() => { el.style.display = 'none'; }, 3000);
        }

        function formatBytes(bytes) {
            let v = Number(bytes || 0);
            const units = ['B', 'KB', 'MB', 'GB', 'TB'];
            let i = 0;
            while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
            return (i > 1 ? v.toFixed(2) : v.toFixed(1)) + ' ' + units[i];
        }

        function esc(str) {
            return String(str || '').replace(/[&<>"']/g, m => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m]));
        }

        function updateOnlineStatus() {
            const dot = document.getElementById('net-dot');
            if (navigator.onLine) dot.classList.remove('offline');
            else dot.classList.add('offline');
        }
        window.addEventListener('online', updateOnlineStatus);
        window.addEventListener('offline', updateOnlineStatus);
        updateOnlineStatus();

        function switchTab(tab) {
            document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
            document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
            document.getElementById('page-' + tab).classList.add('active');
            document.getElementById('nav-' + tab).classList.add('active');
            if (tab === 'offline') renderOfflineList();
        }

        function triggerCamera() {
            switchTab('upload');
            setTimeout(() => document.getElementById('picker-camera').click(), 120);
        }

        function openNoteSheet() {
            document.getElementById('note-sheet').classList.add('open');
        }

        async function handleLogin(e) {
            e.preventDefault();
            const u = document.getElementById('login-user').value.trim();
            const p = document.getElementById('login-pass').value;
            const btn = document.getElementById('login-btn');
            btn.innerText = 'Ověřování...';
            SESSION = { username: u, password: p };
            const ok = await syncAll();
            btn.innerText = 'Přihlásit se';
            if (ok) {
                localStorage.setItem('vg_mob_user', u);
                localStorage.setItem('vg_mob_pass', p);
                document.getElementById('login-screen').style.display = 'none';
                processIncomingSharedFiles();
            } else {
                showToast('Chybné jméno nebo heslo');
            }
        }

        function logout() {
            localStorage.removeItem('vg_mob_user');
            localStorage.removeItem('vg_mob_pass');
            location.reload();
        }

        async function syncAll() {
            if (!SESSION.username || !SESSION.password) return false;
            if (!navigator.onLine) {
                document.getElementById('login-screen').style.display = 'none';
                switchTab('offline');
                showToast('Offline režim — otevřen lokální trezor');
                return true;
            }
            try {
                const fd = new FormData();
                fd.append('username', SESSION.username);
                fd.append('password', SESSION.password);
                const res = await fetch('/api/mobile/bootstrap', { method: 'POST', body: fd });
                if (!res.ok) return false;
                const data = await res.json();
                if (!data.ok) return false;

                STATE.files = data.files || [];
                STATE.folders = data.folders || ['/'];
                STATE.usedBytes = data.used_bytes || 0;
                STATE.quotaBytes = data.quota_bytes || 0;

                document.getElementById('header-text').innerText = 'VaultGrid • ' + SESSION.username;
                renderAll();
                return true;
            } catch (e) {
                return false;
            }
        }

        function renderAll() {
            // Home KPI
            document.getElementById('home-used').innerText = formatBytes(STATE.usedBytes);
            document.getElementById('home-quota').innerText = STATE.quotaBytes > 0 ? ('Kvóta: ' + formatBytes(STATE.quotaBytes)) : 'Kvóta: Bez limitu';
            document.getElementById('home-count').innerText = STATE.files.length;

            // Upload folder select
            const sel = document.getElementById('upload-folder');
            const prev = sel.value;
            sel.innerHTML = STATE.folders.map(f => `<option value="${esc(f)}">${esc(f)}</option>`).join('');
            if (STATE.folders.includes(prev)) sel.value = prev;
            else if (STATE.folders.includes('/Camera')) sel.value = '/Camera';

            // Recent files
            const recent = STATE.files.slice(0, 6);
            document.getElementById('home-recent').innerHTML = recent.length
                ? recent.map(renderFileCard).join('')
                : '<div style="color:var(--muted); text-align:center; padding:20px;">Zatím žádné soubory.</div>';

            // Folder chips
            const allChips = ['ALL', ...STATE.folders];
            document.getElementById('folder-chips').innerHTML = allChips.map(f => {
                const label = f === 'ALL' ? 'Všechny soubory' : f;
                const cls = STATE.currentFolder === f ? 'chip active' : 'chip';
                return `<div class="${cls}" onclick="selectFolder('${esc(f)}')">${esc(label)}</div>`;
            }).join('');

            renderFilesList();
            renderMediaTab();
        }

        function selectFolder(fld) {
            STATE.currentFolder = fld;
            renderAll();
        }

        function renderFilesList() {
            const q = (document.getElementById('search-input').value || '').trim().toLowerCase();
            let list = STATE.files;
            if (STATE.currentFolder !== 'ALL') {
                list = list.filter(f => f.folder === STATE.currentFolder);
            }
            if (q) {
                if (q.startsWith('#')) {
                    const tag = q.slice(1);
                    list = list.filter(f => (f.tags || []).includes(tag));
                } else {
                    list = list.filter(f => f.filename.toLowerCase().includes(q));
                }
            }
            document.getElementById('files-list').innerHTML = list.length
                ? list.map(renderFileCard).join('')
                : '<div style="color:var(--muted); text-align:center; padding:24px;">Žádné soubory v tomto zobrazení.</div>';
        }

        function renderFileCard(f) {
            let thumb = `<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>`;
            if (f.type === 'image' && !f.encrypted && f.file_url.startsWith('http')) {
                thumb = `<img src="${esc(f.file_url)}" loading="lazy">`;
            } else if (f.encrypted) {
                thumb = `<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#f59e0b" stroke-width="2.2"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>`;
            } else if (f.type === 'video') {
                thumb = `<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#60a5fa" stroke-width="2.2"><polygon points="5 3 19 12 5 21 5 3"/></svg>`;
            }
            const tagsHtml = (f.tags || []).map(t => `<span style="color:var(--accent);">#${esc(t)}</span>`).join(' ');
            return `
            <div class="file-row" onclick="previewFile(${f.id})">
                <div class="file-thumb">${thumb}</div>
                <div class="file-meta">
                    <div class="file-name">${esc(f.filename)}</div>
                    <div class="file-sub">
                        <span>${formatBytes(f.size)}</span>
                        <span>•</span>
                        <span>${esc(f.folder)}</span>
                        ${tagsHtml}
                    </div>
                </div>
                <button type="button" class="more-btn" onclick="event.stopPropagation(); openFileSheet(${f.id})">
                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4"><circle cx="12" cy="12" r="1"/><circle cx="12" cy="5" r="1"/><circle cx="12" cy="19" r="1"/></svg>
                </button>
            </div>`;
        }

        function renderMediaTab() {
            const photos = STATE.files.filter(f => f.type === 'image' && !f.encrypted && f.file_url.startsWith('http'));
            document.getElementById('media-photos').innerHTML = photos.length
                ? photos.map(p => `<div class="photo-cell" onclick="previewFile(${p.id})"><img src="${esc(p.file_url)}" loading="lazy"></div>`).join('')
                : '<div style="grid-column:1/-1; color:var(--muted); padding:14px;">Žádné fotografie.</div>';

            const av = STATE.files.filter(f => (f.type === 'video' || f.type === 'audio') && !f.encrypted);
            document.getElementById('media-av').innerHTML = av.length
                ? av.map(renderFileCard).join('')
                : '<div style="color:var(--muted); padding:14px;">Žádná videa ani hudba.</div>';
        }

        // NAHRÁVÁNÍ S UKAZATELEM RYCHLOSTI A PROCENT
        async function handleSelectedFiles(fileList) {
            if (!fileList || !fileList.length) return;
            const folder = document.getElementById('upload-folder').value || '/Camera';
            const encPass = document.getElementById('upload-enc-chk').checked ? document.getElementById('upload-enc-pass').value : '';
            const box = document.getElementById('upload-progress-box');
            const bar = document.getElementById('up-bar');
            const pct = document.getElementById('up-pct');
            const st = document.getElementById('up-status');
            box.style.display = 'block';

            for (let i = 0; i < fileList.length; i++) {
                const file = fileList[i];
                st.innerText = `Nahrávám (${i + 1}/${fileList.length}): ${file.name}`;
                bar.style.width = '0%';
                pct.innerText = '0%';

                await new Promise((resolve) => {
                    const xhr = new XMLHttpRequest();
                    const fd = new FormData();
                    fd.append('username', SESSION.username);
                    fd.append('password', SESSION.password);
                    fd.append('folder', folder);
                    fd.append('encrypt_pass', encPass);
                    fd.append('file', file);

                    xhr.upload.onprogress = (ev) => {
                        if (ev.lengthComputable) {
                            const p = Math.round((ev.loaded / ev.total) * 100);
                            bar.style.width = p + '%';
                            pct.innerText = p + '%';
                        }
                    };
                    xhr.onload = () => resolve();
                    xhr.onerror = () => resolve();
                    xhr.open('POST', '/api/mobile/upload');
                    xhr.send(fd);
                });
            }

            st.innerText = 'Hotovo! Vše uloženo v cloudu.';
            showToast(`Nahráno souborů: ${fileList.length}`);
            await syncAll();
        }

        // ZPRACOVÁNÍ SOUBORŮ SDÍLENÝCH Z GALERIE TELEFONU (WEB SHARE TARGET)
        async function processIncomingSharedFiles() {
            const params = new URLSearchParams(location.search);
            if (!params.has('shared')) return;
            history.replaceState({}, '', '/');
            try {
                const db = await new Promise((resolve, reject) => {
                    const req = indexedDB.open('vg_share_queue', 1);
                    req.onupgradeneeded = () => req.result.createObjectStore('queue', { autoIncrement: true });
                    req.onsuccess = () => resolve(req.result);
                    req.onerror = () => reject(req.error);
                });
                const tx = db.transaction('queue', 'readwrite');
                const store = tx.objectStore('queue');
                const items = await new Promise((res) => {
                    const r = store.getAll();
                    r.onsuccess = () => res(r.result || []);
                });
                store.clear();
                if (items.length > 0) {
                    switchTab('upload');
                    const files = items.map(it => new File([it.file], it.name, { type: it.type || 'application/octet-stream' }));
                    await handleSelectedFiles(files);
                }
            } catch (e) {}
        }

        async function createNewFolderPrompt() {
            const name = prompt('Název nové složky (např. Dovolená):');
            if (!name || !name.trim()) return;
            const fd = new FormData();
            fd.append('username', SESSION.username);
            fd.append('password', SESSION.password);
            fd.append('parent_folder', '/');
            fd.append('name', name.trim());
            await fetch('/api/mobile/create-folder', { method: 'POST', body: fd });
            showToast('Složka vytvořena');
            await syncAll();
        }

        async function saveQuickNote() {
            const title = document.getElementById('note-title').value;
            const content = document.getElementById('note-body').value;
            if (!content.trim()) return;
            const fd = new FormData();
            fd.append('username', SESSION.username);
            fd.append('password', SESSION.password);
            fd.append('title', title);
            fd.append('content', content);
            await fetch('/api/mobile/quick-note', { method: 'POST', body: fd });
            document.getElementById('note-title').value = '';
            document.getElementById('note-body').value = '';
            document.getElementById('note-sheet').classList.remove('open');
            showToast('Poznámka uložena do /Notes');
            await syncAll();
        }

        // ACTION SHEET PRO SOUBOR
        function openFileSheet(id) {
            const f = STATE.files.find(x => x.id === id);
            if (!f) return;
            document.getElementById('sheet-filename').innerText = f.filename;
            let btns = `
                <button class="sheet-action" onclick="closeSheet(); previewFile(${f.id})">Otevřít náhled</button>
                <button class="sheet-action" onclick="closeSheet(); saveFileOffline(${f.id})">Uložit do Offline trezoru v telefonu</button>
                <button class="sheet-action" onclick="closeSheet(); shareVaultDrop(${f.id})">Sdílet odkaz (VaultDrop / WhatsApp)</button>
            `;
            if (f.encrypted) {
                btns += `<button class="sheet-action" onclick="closeSheet(); decryptDownload(${f.id})">Dešifrovat a stáhnout (AES-256)</button>`;
            } else {
                btns += `<a href="${esc(f.file_url)}" download="${esc(f.filename)}" class="sheet-action" style="text-decoration:none;" onclick="closeSheet()">Stáhnout do telefonu</a>`;
            }
            btns += `<button class="sheet-action" style="color:#f87171;" onclick="closeSheet(); deleteFile(${f.id})">Přesunout do koše</button>`;
            document.getElementById('sheet-buttons').innerHTML = btns;
            document.getElementById('action-sheet').classList.add('open');
        }
        function closeSheet() {
            document.getElementById('action-sheet').classList.remove('open');
        }

        async function shareVaultDrop(id) {
            showToast('Generuji sdílecí odkaz...');
            const fd = new FormData();
            fd.append('username', SESSION.username);
            fd.append('password', SESSION.password);
            fd.append('file_id', id);
            fd.append('expire_hours', '24');
            const res = await fetch('/api/mobile/vaultdrop', { method: 'POST', body: fd });
            const data = await res.json();
            if (data.ok && data.share_url) {
                if (navigator.share) {
                    navigator.share({ title: data.filename, url: data.share_url }).catch(() => {});
                } else {
                    await navigator.clipboard.writeText(data.share_url);
                    showToast('Odkaz zkopírován do schránky!');
                }
            }
        }

        async function decryptDownload(id) {
            const pass = prompt('Zadejte dešifrovací heslo VaultCrypt:');
            if (!pass) return;
            const fd = new FormData();
            fd.append('username', SESSION.username);
            fd.append('password', SESSION.password);
            fd.append('file_id', id);
            fd.append('decrypt_pass', pass);
            const res = await fetch('/api/mobile/decrypt', { method: 'POST', body: fd });
            if (!res.ok) {
                showToast('Chybné dešifrovací heslo!');
                return;
            }
            const blob = await res.blob();
            const f = STATE.files.find(x => x.id === id);
            const orig = f ? f.filename.replace(/\.vgenc$/, '') : 'decrypted_file';
            const a = document.createElement('a');
            a.href = URL.createObjectURL(blob);
            a.download = orig;
            a.click();
        }

        async function deleteFile(id) {
            const fd = new FormData();
            fd.append('username', SESSION.username);
            fd.append('password', SESSION.password);
            fd.append('file_id', id);
            await fetch('/api/mobile/delete', { method: 'POST', body: fd });
            showToast('Přesunuto do koše');
            await syncAll();
        }

        // FULLSCREEN NÁHLED (OBRÁZKY, VIDEO, AUDIO, PDF, TEXT)
        async function previewFile(id) {
            const f = STATE.files.find(x => x.id === id);
            if (!f) return;
            if (f.encrypted) {
                decryptDownload(id);
                return;
            }
            const lb = document.getElementById('lightbox');
            const body = document.getElementById('lb-body');
            document.getElementById('lb-title').innerText = f.filename;

            if (f.type === 'image') {
                body.innerHTML = `<img src="${esc(f.file_url)}" style="max-width:100%; max-height:100%; object-fit:contain;">`;
            } else if (f.type === 'video') {
                body.innerHTML = `<video src="${esc(f.file_url)}" controls autoplay playsinline style="width:100%; max-height:100%;"></video>`;
            } else if (f.type === 'audio') {
                body.innerHTML = `<audio src="${esc(f.file_url)}" controls autoplay style="width:90%;"></audio>`;
            } else if (f.type === 'pdf') {
                body.innerHTML = `<iframe src="${esc(f.file_url)}" style="width:100%; height:100%; border:none; background:#fff;"></iframe>`;
            } else if (f.type === 'text') {
                body.innerHTML = '<div style="color:#fff;">Načítání textu...</div>';
                lb.classList.add('open');
                const txt = await (await fetch(f.file_url)).text();
                body.innerHTML = `<pre style="color:#e5e7eb; font-family:monospace; font-size:13px; white-space:pre-wrap; width:100%; height:100%; overflow:auto; margin:0; padding:12px;">${esc(txt)}</pre>`;
                return;
            } else {
                body.innerHTML = `<div style="text-align:center; color:#fff;"><p>${esc(f.filename)} (${formatBytes(f.size)})</p><a href="${esc(f.file_url)}" download class="btn">Stáhnout soubor</a></div>`;
            }
            lb.classList.add('open');
        }
        function closeLightbox() {
            document.getElementById('lb-body').innerHTML = '';
            document.getElementById('lightbox').classList.remove('open');
        }

        // OFFLINE TREZOR (INDEXEDDB)
        function openOfflineDB() {
            return new Promise((resolve, reject) => {
                const req = indexedDB.open('vg_offline_vault', 1);
                req.onupgradeneeded = () => req.result.createObjectStore('files', { keyPath: 'id' });
                req.onsuccess = () => resolve(req.result);
                req.onerror = () => reject(req.error);
            });
        }

        async function saveFileOffline(id) {
            const f = STATE.files.find(x => x.id === id);
            if (!f) return;
            showToast('Stahuji pro offline použití...');
            try {
                const resp = await fetch(f.file_url);
                const blob = await resp.blob();
                const db = await openOfflineDB();
                const tx = db.transaction('files', 'readwrite');
                tx.objectStore('files').put({ id: f.id, filename: f.filename, type: f.type, size: blob.size, blob: blob });
                await new Promise(r => tx.oncomplete = r);
                showToast('Uloženo v Offline trezoru');
            } catch (e) {
                showToast('Chyba při ukládání offline');
            }
        }

        async function renderOfflineList() {
            const db = await openOfflineDB();
            const tx = db.transaction('files', 'readonly');
            const items = await new Promise(r => {
                const req = tx.objectStore('files').getAll();
                req.onsuccess = () => r(req.result || []);
            });
            const box = document.getElementById('offline-list');
            if (!items.length) {
                box.innerHTML = '<div style="color:var(--muted); text-align:center; padding:16px;">Offline trezor je prázdný. U libovolného souboru klepni na ⋮ → Uložit do Offline trezoru.</div>';
                return;
            }
            box.innerHTML = items.map(it => `
                <div class="file-row" onclick="openOfflineItem(${it.id})">
                    <div class="file-thumb">OFF</div>
                    <div class="file-meta">
                        <div class="file-name">${esc(it.filename)}</div>
                        <div class="file-sub">${formatBytes(it.size)} • Dostupný bez internetu</div>
                    </div>
                    <button type="button" class="more-btn" style="color:#f87171;" onclick="event.stopPropagation(); removeOfflineItem(${it.id})">✕</button>
                </div>
            `).join('');
        }

        async function openOfflineItem(id) {
            const db = await openOfflineDB();
            const tx = db.transaction('files', 'readonly');
            const it = await new Promise(r => {
                const req = tx.objectStore('files').get(id);
                req.onsuccess = () => r(req.result);
            });
            if (!it) return;
            const url = URL.createObjectURL(it.blob);
            const lb = document.getElementById('lightbox');
            const body = document.getElementById('lb-body');
            document.getElementById('lb-title').innerText = '[OFFLINE] ' + it.filename;
            if (it.type === 'image') body.innerHTML = `<img src="${url}" style="max-width:100%; max-height:100%;">`;
            else if (it.type === 'pdf') body.innerHTML = `<iframe src="${url}" style="width:100%; height:100%; border:none; background:#fff;"></iframe>`;
            else if (it.type === 'video') body.innerHTML = `<video src="${url}" controls autoplay playsinline style="width:100%;"></video>`;
            else body.innerHTML = `<a href="${url}" download="${esc(it.filename)}" class="btn">Otevřít / Uložit soubor</a>`;
            lb.classList.add('open');
        }

        async function removeOfflineItem(id) {
            const db = await openOfflineDB();
            const tx = db.transaction('files', 'readwrite');
            tx.objectStore('files').delete(id);
            await new Promise(r => tx.oncomplete = r);
            renderOfflineList();
            showToast('Odebráno z offline trezoru');
        }

        // AUTOMATICKÉ PŘIHLÁŠENÍ PŘI STARTU PWA
        (async function init() {
            const params = new URLSearchParams(location.search);
            if (SESSION.username && SESSION.password) {
                const ok = await syncAll();
                if (ok) {
                    document.getElementById('login-screen').style.display = 'none';
                    if (params.get('action') === 'camera') triggerCamera();
                    else if (params.get('tab') === 'offline') switchTab('offline');
                    await processIncomingSharedFiles();
                }
            }
        })();
    </script>
</body>
</html>"""

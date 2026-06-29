import asyncio
import io
import logging
import json
import os
import threading
import time
import datetime
import html
import re
import socket
import aiohttp
from aiohttp import web
from deltachat2 import events, MsgData
from deltabot_cli import BotCli

import database

# Initialize logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("uptime_bot")

dc_cli = BotCli("uptimebot")
bot_qr_cache = {}

# Global references
dc_bot_instance = None
dc_accid = None

# Async event loop and task tracking for check scheduler
async_event_loop = None
running_resource_ids = set()
running_lock = asyncio.Lock()

# Custom command parsing configuration
ALLOWED_PREFIXES = ["up", "uptime"]

def setup_custom_command_parser(bot, allowed_prefixes):
    original_parse_command = bot._parse_command

    def custom_parse_command(accid: int, event) -> None:
        text = event.msg.text
        if not text:
            original_parse_command(accid, event)
            return

        parts = text.split(maxsplit=1)
        cmd = parts[0]
        
        if "@" in cmd:
            cmd_name, suffix = cmd.split("@", 1)
            suffix_lower = suffix.lower()
            
            if suffix_lower:
                try:
                    self_address = bot.rpc.get_contact(accid, 1).address.lower()
                except Exception:
                    self_address = ""
                
                matched = False
                for p in allowed_prefixes:
                    if suffix_lower.startswith(p.lower()) or p.lower().startswith(suffix_lower):
                        matched = True
                        break
                if not matched and self_address and suffix_lower == self_address:
                    matched = True
                
                if matched:
                    new_text = cmd_name
                    if len(parts) > 1:
                        new_text += " " + parts[1]
                    
                    original_text = event.msg.text
                    event.msg["text"] = new_text
                    try:
                        original_parse_command(accid, event)
                    finally:
                        event.msg["text"] = original_text
                else:
                    event.command = ""
                    event.payload = ""
            else:
                original_parse_command(accid, event)
        else:
            original_parse_command(accid, event)
            
            if event.command in ("/help", "/status", "/list"):
                try:
                    chat = bot.rpc.get_chat(accid, event.msg.chat_id)
                    is_group = getattr(chat, "chat_type", "Single") != "Single"
                except Exception:
                    is_group = False
                
                if is_group:
                    try:
                        contacts = bot.rpc.get_chat_contacts(accid, event.msg.chat_id)
                        bot_count = 0
                        for contact_id in contacts:
                            if contact_id == 1:
                                bot_count += 1
                                continue
                            c = bot.rpc.get_contact(accid, contact_id)
                            if getattr(c, "is_bot", False):
                                bot_count += 1
                                if bot_count > 1:
                                    break
                        if bot_count > 1:
                            event.command = ""
                            event.payload = ""
                    except Exception:
                        pass

    bot._parse_command = custom_parse_command

# Helper: format time durations
def format_duration(seconds: int) -> str:
    if seconds < 60:
        return f"{seconds}s"
    elif seconds < 3600:
        return f"{seconds // 60}m {seconds % 60}s"
    else:
        hours = seconds // 3600
        mins = (seconds % 3600) // 60
        return f"{hours}h {mins}m"

# Helper: parse add targets
def parse_target(target: str) -> tuple[str, str]:
    target = target.strip()
    if not target:
        raise ValueError("Target is empty")
        
    if target.startswith("http://") or target.startswith("https://"):
        return "http", target
        
    if ":" in target:
        parts = target.rsplit(":", 1)
        if len(parts) == 2 and parts[1].isdigit():
            port = int(parts[1])
            if 1 <= port <= 65535:
                return "tcp", target
                
    host = target
    if not re.match(r'^[a-zA-Z0-9.-]+$', host):
        raise ValueError("Invalid target format. Provide an HTTP/HTTPS URL, a host:port, or a hostname/IP.")
    return "ping", host

# Admin detection helper
def _get_contact_fingerprint(bot, accid, contact_id, contact=None):
    try:
        self_fps = []
        try:
            self_enc = bot.rpc.get_contact_encryption_info(accid, 1)
            if self_enc:
                self_fps = [m.upper() for m in re.findall(r'[0-9a-fA-F]{32,64}', "".join(self_enc.split()).replace(':', ''))]
        except Exception:
            pass

        if contact:
            get_val = getattr(contact, 'get', lambda k: getattr(contact, k, None))
            for attr in ['fingerprint', 'key_fingerprint', 'public_key']:
                val = get_val(attr)
                if val:
                    matches = re.findall(r'[0-9a-fA-F]{32,64}', str(val).replace(' ', '').replace(':', ''))
                    valid_matches = [m.upper() for m in matches if m.upper() not in self_fps]
                    if valid_matches:
                        return ",".join(valid_matches)

        try:
            fp = bot.rpc.get_contact_config(accid, contact_id, "fp")
            if fp and fp.upper().replace(' ', '') not in self_fps:
                return fp.upper().replace(' ', '')
        except Exception:
            pass

        for args in [(accid, contact_id), (contact_id,)]:
            try:
                enc_info = bot.rpc.get_contact_encryption_info(*args)
                if enc_info:
                    cleaned_info = "".join(enc_info.split()).replace(':', '')
                    matches = re.findall(r'[0-9a-fA-F]{32,64}', cleaned_info)
                    valid_matches = [m.upper() for m in matches if m.upper() not in self_fps]
                    if valid_matches:
                        return ",".join(valid_matches)
            except Exception:
                continue
    except Exception as e:
        logger.error(f"Error checking fingerprint: {e}")
    return None

def _is_dc_admin(bot, accid, contact_id):
    try:
        contact = None
        try:
            contact = bot.rpc.get_contact(accid, contact_id)
        except Exception:
            pass
        
        admin_fp = database.get_admin_fingerprint()
        if admin_fp:
            c_fp = _get_contact_fingerprint(bot, accid, contact_id, contact=contact)
            if c_fp:
                if admin_fp.upper() in c_fp.upper().split(','):
                    return True
            if c_fp:
                 logger.warning(f"Admin fingerprint mismatch for contact {contact_id}")
                 return False
        
        if contact:
            sender_email = contact.address
            admin_email = database.get_config("admin_dc_email")
            if admin_email and admin_email.lower() == sender_email.lower():
                return True
            
    except Exception as e:
        logger.error(f"Error during admin verification: {e}")
    return False

# Uptime checks execution logic
async def run_single_check(resource) -> tuple[bool, str]:
    rtype = resource["type"]
    url = resource["url"]
    timeout = 10
    
    try:
        if rtype == "http":
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=timeout)) as session:
                async with session.get(url, allow_redirects=True) as resp:
                    if 200 <= resp.status < 400:
                        return True, f"HTTP {resp.status}"
                    else:
                        return False, f"HTTP {resp.status}"
        elif rtype == "tcp":
            parts = url.rsplit(":", 1)
            host, port = parts[0], int(parts[1])
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=timeout
            )
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return True, "Connected"
        elif rtype == "ping":
            host = url.strip()
            if not re.match(r'^[a-zA-Z0-9.-]+$', host):
                return False, "Invalid hostname format"
            proc = await asyncio.create_subprocess_exec(
                "ping", "-c", "1", "-W", "2", host,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL
            )
            await proc.wait()
            if proc.returncode == 0:
                return True, "Ping successful"
            else:
                return False, "Ping failed"
    except asyncio.TimeoutError:
        return False, "Timeout"
    except Exception as e:
        return False, str(e)
    return False, "Unknown error"

async def check_resource_task(resource, semaphore):
    async with semaphore:
        is_up, error_msg = await run_single_check(resource)
        
        # Retry logic: 2 retries, 30s apart, if failed and previously not down
        if not is_up and resource["status"] != "down":
            for retry in range(1, 3):
                await asyncio.sleep(30)
                is_up, error_msg = await run_single_check(resource)
                if is_up:
                    break
        
        await handle_check_result(resource, is_up, error_msg)

async def handle_check_result(resource, is_up, error_msg):
    status = "up" if is_up else "down"
    old_status = resource["status"]
    
    failures = 0 if is_up else (resource["consecutive_failures"] + 1)
    await asyncio.to_thread(database.update_resource_status, resource["id"], status, failures)
    
    if old_status != status and old_status != "unknown":
        await notify_status_change(resource, old_status, status, error_msg)

async def notify_status_change(resource, old_status, status, error_msg):
    name = resource["name"] or resource["url"]
    url = resource["url"]
    chat_id = resource["dc_chat_id"]
    
    if status == "down":
        msg_text = (
            f"🔴 **Service is DOWN**\n\n"
            f"🖥️ Name: **{name}**\n"
            f"🔗 Target: `{url}`\n"
            f"⚠️ Type: `{resource['type'].upper()}`\n"
            f"❌ Error: `{error_msg}`\n"
            f"🕒 Time: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        )
    else:
        last_changed = resource["last_changed"]
        duration_str = "unknown"
        if last_changed:
            duration_secs = int(time.time()) - last_changed
            duration_str = format_duration(duration_secs)
            
        msg_text = (
            f"🟢 **Service is UP** (Recovered)\n\n"
            f"🖥️ Name: **{name}**\n"
            f"🔗 Target: `{url}`\n"
            f"🕒 Duration offline: `{duration_str}`\n"
            f"🕒 Time: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        )
        
    if dc_bot_instance and dc_accid is not None:
        try:
            await asyncio.to_thread(
                dc_bot_instance.rpc.send_msg,
                dc_accid,
                chat_id,
                MsgData(text=msg_text)
            )
        except Exception as e:
            logger.error(f"Failed to send status alert to chat {chat_id}: {e}")

async def run_and_track_check(resource, semaphore):
    try:
        await check_resource_task(resource, semaphore)
    finally:
        async with running_lock:
            running_resource_ids.discard(resource["id"])

async def run_checks_parallel(tasks_list):
    await asyncio.gather(*tasks_list, return_exceptions=True)

async def monitoring_scheduler_loop():
    semaphore = asyncio.Semaphore(50)
    while True:
        try:
            resources = await asyncio.to_thread(database.get_all_resources)
            now = int(time.time())
            
            tasks = []
            async with running_lock:
                for r in resources:
                    r_id = r["id"]
                    if r_id in running_resource_ids:
                        continue
                        
                    last_checked = r["last_checked"] or 0
                    interval = r["interval"] or 60
                    
                    if now - last_checked >= interval:
                        running_resource_ids.add(r_id)
                        tasks.append(run_and_track_check(r, semaphore))
                    
            if tasks:
                logger.info(f"Triggering {len(tasks)} resource checks...")
                asyncio.create_task(run_checks_parallel(tasks))
                
        except Exception as e:
            logger.error(f"Error in monitoring scheduler loop: {e}")
            
        await asyncio.sleep(5)

# Web Server handling and dashboard HTML templates
def get_dashboard_html(chat_name, resources, overall_uptime) -> str:
    total_monitors = len(resources)
    down_monitors = sum(1 for r in resources if r["status"] == "down")
    
    status_badge_class = "all-up" if down_monitors == 0 else "some-down"
    status_text = "All Systems Operational" if down_monitors == 0 else f"{down_monitors} Service(s) Offline"
    status_indicator = "up" if down_monitors == 0 else "down"
    
    monitors_html = ""
    if total_monitors == 0:
        monitors_html = """
        <div class="empty-state">
            <div class="empty-icon">🔍</div>
            <p>No resources are being monitored in this chat yet.</p>
            <p style="font-size: 0.875rem; margin-top: 0.5rem;">Use <code>/add &lt;target&gt; [name]</code> in Delta Chat to add your first monitor.</p>
        </div>
        """
    else:
        for r in resources:
            r_uptime = database.get_resource_uptime_30d(r["id"])
            indicator_class = "up" if r["status"] == "up" else ("down" if r["status"] == "down" else "unknown")
            status_lbl = r["status"].upper()
            
            last_checked_str = "Never"
            if r["last_checked"]:
                last_checked_str = datetime.datetime.fromtimestamp(r["last_checked"]).strftime('%Y-%m-%d %H:%M:%S')
                
            monitors_html += f"""
            <div class="monitor-card">
                <div class="monitor-info">
                    <span class="indicator {indicator_class}"></span>
                    <div class="monitor-meta">
                        <span class="monitor-name">{html.escape(r["name"] or r["url"])}</span>
                        <span class="monitor-url">{html.escape(r["url"])}</span>
                        <span class="monitor-type">{r["type"]}</span>
                    </div>
                </div>
                <div class="monitor-stats">
                    <div class="m-stat">
                        <span class="m-val" style="color: { 'var(--color-up)' if r["status"] == "up" else 'var(--color-down)' if r["status"] == "down" else 'var(--text-muted)' };">{status_lbl}</span>
                        <span class="m-lbl">Status</span>
                    </div>
                    <div class="m-stat">
                        <span class="m-val">{r_uptime:.2f}%</span>
                        <span class="m-lbl">Uptime 30d</span>
                    </div>
                    <div class="m-stat">
                        <span class="m-val" style="font-size: 0.875rem;">{last_checked_str}</span>
                        <span class="m-lbl">Last Checked</span>
                    </div>
                </div>
            </div>
            """
            
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Delta Chat Uptime Monitor - {html.escape(chat_name)}</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;600;700&display=swap" rel="stylesheet">
    <style>
        :root {{
            --bg-color: #0b0f19;
            --card-bg: rgba(20, 26, 42, 0.6);
            --border-color: rgba(255, 255, 255, 0.08);
            --text-main: #f3f4f6;
            --text-muted: #9ca3af;
            --color-up: #10b981;
            --color-down: #ef4444;
            --color-warn: #f59e0b;
            --glow-up: rgba(16, 185, 129, 0.4);
            --glow-down: rgba(239, 68, 68, 0.4);
            --glow-warn: rgba(245, 158, 11, 0.4);
        }}
        
        * {{
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }}
        
        body {{
            font-family: 'Outfit', sans-serif;
            background-color: var(--bg-color);
            color: var(--text-main);
            min-height: 100vh;
            display: flex;
            flex-direction: column;
            justify-content: space-between;
            background-image: 
                radial-gradient(circle at 10% 20%, rgba(16, 185, 129, 0.05) 0%, transparent 40%),
                radial-gradient(circle at 90% 80%, rgba(59, 130, 246, 0.05) 0%, transparent 40%);
        }}
        
        header {{
            padding: 2rem 1.5rem;
            max-width: 1200px;
            width: 100%;
            margin: 0 auto;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        
        .logo-container {{
            display: flex;
            align-items: center;
            gap: 0.75rem;
        }}
        
        .logo-icon {{
            font-size: 1.75rem;
        }}
        
        .logo-title {{
            font-size: 1.5rem;
            font-weight: 700;
            background: linear-gradient(135deg, #3b82f6, #10b981);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }}
        
        main {{
            flex-grow: 1;
            max-width: 1200px;
            width: 100%;
            margin: 0 auto;
            padding: 0 1.5rem 3rem;
        }}
        
        .stats-panel {{
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 1rem;
            padding: 2rem;
            backdrop-filter: blur(12px);
            margin-bottom: 2rem;
            display: flex;
            flex-direction: column;
            gap: 1.5rem;
            position: relative;
            overflow: hidden;
        }}
        
        .stats-panel::before {{
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 3px;
            background: linear-gradient(90deg, #3b82f6, #10b981);
        }}
        
        .stats-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 1rem;
        }}
        
        .status-badge {{
            display: flex;
            align-items: center;
            gap: 0.5rem;
            font-size: 1.125rem;
            font-weight: 600;
            padding: 0.5rem 1rem;
            border-radius: 2rem;
            background: rgba(255, 255, 255, 0.04);
            border: 1px solid var(--border-color);
        }}
        
        .status-badge.all-up {{
            color: var(--color-up);
            border-color: rgba(16, 185, 129, 0.2);
            background: rgba(16, 185, 129, 0.05);
        }}
        
        .status-badge.some-down {{
            color: var(--color-down);
            border-color: rgba(239, 68, 68, 0.2);
            background: rgba(239, 68, 68, 0.05);
        }}
        
        .indicator {{
            width: 10px;
            height: 10px;
            border-radius: 50%;
            display: inline-block;
        }}
        
        .indicator.up {{
            background-color: var(--color-up);
            box-shadow: 0 0 12px var(--glow-up);
            animation: pulse-green 2s infinite;
        }}
        
        .indicator.down {{
            background-color: var(--color-down);
            box-shadow: 0 0 12px var(--glow-down);
            animation: pulse-red 2s infinite;
        }}
        
        .indicator.unknown {{
            background-color: var(--text-muted);
        }}
        
        @keyframes pulse-green {{
            0% {{ box-shadow: 0 0 0 0 rgba(16, 185, 129, 0.4); }}
            70% {{ box-shadow: 0 0 0 8px rgba(16, 185, 129, 0); }}
            100% {{ box-shadow: 0 0 0 0 rgba(16, 185, 129, 0); }}
        }}
        
        @keyframes pulse-red {{
            0% {{ box-shadow: 0 0 0 0 rgba(239, 68, 68, 0.4); }}
            70% {{ box-shadow: 0 0 0 8px rgba(239, 68, 68, 0); }}
            100% {{ box-shadow: 0 0 0 0 rgba(239, 68, 68, 0); }}
        }}
        
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1.5rem;
        }}
        
        .stat-card {{
            background: rgba(255, 255, 255, 0.02);
            border: 1px solid var(--border-color);
            border-radius: 0.75rem;
            padding: 1.25rem;
            display: flex;
            flex-direction: column;
            gap: 0.25rem;
        }}
        
        .stat-val {{
            font-size: 2rem;
            font-weight: 700;
        }}
        
        .stat-lbl {{
            font-size: 0.875rem;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }}
        
        .monitors-title {{
            font-size: 1.25rem;
            font-weight: 600;
            margin-bottom: 1rem;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }}
        
        .monitors-grid {{
            display: grid;
            grid-template-columns: 1fr;
            gap: 1rem;
        }}
        
        .monitor-card {{
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 0.75rem;
            padding: 1.5rem;
            backdrop-filter: blur(12px);
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 1rem;
            transition: transform 0.2s, border-color 0.2s;
        }}
        
        .monitor-card:hover {{
            transform: translateY(-2px);
            border-color: rgba(255, 255, 255, 0.15);
        }}
        
        .monitor-info {{
            display: flex;
            align-items: center;
            gap: 1rem;
            min-width: 250px;
        }}
        
        .monitor-meta {{
            display: flex;
            flex-direction: column;
            gap: 0.25rem;
        }}
        
        .monitor-name {{
            font-size: 1.125rem;
            font-weight: 600;
        }}
        
        .monitor-url {{
            font-size: 0.875rem;
            color: var(--text-muted);
            word-break: break-all;
        }}
        
        .monitor-type {{
            font-size: 0.75rem;
            font-weight: 700;
            text-transform: uppercase;
            padding: 0.15rem 0.5rem;
            border-radius: 0.25rem;
            background: rgba(255, 255, 255, 0.05);
            width: max-content;
        }}
        
        .monitor-stats {{
            display: flex;
            gap: 2rem;
            align-items: center;
            flex-wrap: wrap;
        }}
        
        .m-stat {{
            display: flex;
            flex-direction: column;
            gap: 0.125rem;
        }}
        
        .m-val {{
            font-size: 1.125rem;
            font-weight: 600;
        }}
        
        .m-lbl {{
            font-size: 0.75rem;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }}
        
        footer {{
            padding: 2rem 1.5rem;
            text-align: center;
            font-size: 0.875rem;
            color: var(--text-muted);
            border-top: 1px solid var(--border-color);
            background: rgba(11, 15, 25, 0.8);
            margin-top: auto;
        }}
        
        footer a {{
            color: #3b82f6;
            text-decoration: none;
        }}
        
        footer a:hover {{
            text-decoration: underline;
        }}
        
        .empty-state {{
            text-align: center;
            padding: 4rem 2rem;
            color: var(--text-muted);
        }}
        
        .empty-icon {{
            font-size: 3rem;
            margin-bottom: 1rem;
        }}
    </style>
</head>
<body>
    <header>
        <div class="logo-container">
            <span class="logo-icon">📊</span>
            <span class="logo-title">Delta Chat Uptime</span>
        </div>
    </header>
    
    <main>
        <div class="stats-panel">
            <div class="stats-header">
                <h2>{html.escape(chat_name)} Status</h2>
                <div class="status-badge {status_badge_class}">
                    <span class="indicator {status_indicator}"></span>
                    <span>{status_text}</span>
                </div>
            </div>
            <div class="stats-grid">
                <div class="stat-card">
                    <span class="stat-val">{overall_uptime:.2f}%</span>
                    <span class="stat-lbl">Uptime 30d</span>
                </div>
                <div class="stat-card">
                    <span class="stat-val">{total_monitors}</span>
                    <span class="stat-lbl">Total Monitors</span>
                </div>
                <div class="stat-card">
                    <span class="stat-val" style="color: var(--color-up);">{up_monitors}</span>
                    <span class="stat-lbl">Online</span>
                </div>
                <div class="stat-card">
                    <span class="stat-val" style="color: { 'var(--color-down)' if down_monitors > 0 else 'var(--text-muted)' };">{down_monitors}</span>
                    <span class="stat-lbl">Offline</span>
                </div>
            </div>
        </div>
        
        <h3 class="monitors-title">⚙️ Monitored Services</h3>
        <div class="monitors-grid">
            {monitors_html}
        </div>
    </main>
    
    <footer>
        <p>Powered by <a href="https://github.com/mrgluek/deltachat_uptime" target="_blank">Delta Chat Uptime Bot</a> (<a href="https://git.gluek.info/gluek/deltachat_uptime" target="_blank">Mirror</a>)</p>
    </footer>
</body>
</html>
"""

async def handle_status_page(request):
    token = request.match_info.get('token')
    chat_id = await asyncio.to_thread(database.get_chat_id_by_token, token)
    if not chat_id:
        return web.Response(text="Status Page Not Found", status=404)
        
    chat_name = "Chat Monitor"
    if dc_bot_instance and dc_accid is not None:
        try:
            chat = await asyncio.to_thread(dc_bot_instance.rpc.get_chat, dc_accid, chat_id)
            chat_name = chat.name
        except Exception:
            pass
            
    resources = await asyncio.to_thread(database.get_resources, chat_id)
    
    # Calculate average uptime
    overall_uptime = 100.0
    if resources:
        uptimes = []
        for r in resources:
            u = await asyncio.to_thread(database.get_resource_uptime_30d, r["id"])
            uptimes.append(u)
        overall_uptime = sum(uptimes) / len(uptimes)
        
    html_content = get_dashboard_html(chat_name, resources, overall_uptime)
    return web.Response(text=html_content, content_type="text/html")

async def _run_web_server():
    app = web.Application()
    app.router.add_get('/{token:[a-zA-Z0-9]{12}}', handle_status_page)
    
    runner = web.AppRunner(app)
    await runner.setup()
    
    port = int(os.getenv("PORT", "8080"))
    site = web.TCPSite(runner, '0.0.0.0', port)
    
    logger.info(f"Starting status page server on 0.0.0.0:{port}...")
    await site.start()
    logger.info("Status page server is running.")
    
    while True:
        await asyncio.sleep(3600)

def start_web_server_thread():
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.run_until_complete(_run_web_server())

def start_monitoring_thread():
    global async_event_loop
    loop = asyncio.new_event_loop()
    async_event_loop = loop
    asyncio.set_event_loop(loop)
    loop.run_until_complete(monitoring_scheduler_loop())

# Command Handlers
def _dc_send_msg_with_stats(bot, accid, chat_id, msg_data):
    try:
        bot.rpc.send_msg(accid, chat_id, msg_data)
        addr = bot.rpc.get_config(accid, "configured_addr") or bot.rpc.get_config(accid, "addr")
        if addr:
            database.increment_transport_sent(addr)
    except Exception as e:
        logger.error(f"Failed to send message: {e}")

@dc_cli.on(events.NewMessage(command="/help"))
def help_command(bot, accid, event):
    msg = event.msg
    is_actually_admin = _is_dc_admin(bot, accid, msg.from_id)
    admin_email = database.get_config("admin_dc_email")
    
    help_text = (
        f"👋 Welcome to Delta Chat Uptime Bot!\n\n"
        f"I monitor resource availability (HTTP, TCP, Ping) and alert this chat if they go offline.\n\n"
        f"**Public Commands:**\n"
        f"/add <target> [name] — Monitor a resource. Target formats:\n"
        f"  • `https://example.com` (HTTP/HTTPS)\n"
        f"  • `example.com:22` (TCP Port)\n"
        f"  • `example.com` (ICMP Ping)\n"
        f"/remove <id> — Stop monitoring a resource\n"
        f"/list — List all monitors in this chat\n"
        f"/status — Show monthly uptime statistics & web link\n"
        f"/donate — Support bot development ❤️\n"
        f"/help — Show this help message\n\n"
    )
    
    if not admin_email:
        help_text += (
            f"**Setup Command:**\n"
            f"/initadmin — Claim bot ownership (admin setup)\n\n"
        )
    elif is_actually_admin:
        admin_fp = database.get_admin_fingerprint()
        fp_suffix = f" ({admin_fp[-8:].upper()})" if admin_fp else ""
        help_text += f"👑 **Admin:** `{admin_email}`{fp_suffix}\n\n"
        help_text += (
            f"**Admin Commands:**\n"
            f"/url [base_url] — Set/view base status URL (e.g. `https://up.gluek.info`)\n"
            f"/accounts — List configured bot accounts\n"
            f"/rmaccount <id> — Delete a bot account\n"
            f"/transports — Show mail relays & stats\n"
            f"/addtransport — Add backup mail relay\n"
            f"/rmtransport <addr> — Remove backup mail relay\n"
            f"/setprimary <addr> — Switch primary relay\n"
            f"/resilient — Toggle multi-transport resilient send\n\n"
        )
        
    help_text += (
        f"**Repository Links:**\n"
        f"GitHub: https://github.com/mrgluek/deltachat_uptime\n"
        f"Mirror: https://git.gluek.info/gluek/deltachat_uptime\n"
    )
    _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text=help_text))

@dc_cli.on(events.NewMessage(command="/donate"))
def donate_command(bot, accid, event):
    msg = event.msg
    _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(
        text="❤️ Support Bot Development\n\n"
             "If you find this bot useful, you can support its development:\n\n"
             "☕️ Ko-fi: https://ko-fi.com/gluek (🌍 world cards, paypal)\n"
             "🚀 Tribute: https://web.tribute.tg/d/IWb (🇷🇺 russian cards, SBP)\n\n"
             "Thank you! 🙏"
    ))

@dc_cli.on(events.NewMessage(command="/initadmin"))
def initadmin_command(bot, accid, event):
    msg = event.msg
    admin_email = database.get_config("admin_dc_email")
    admin_fp = database.get_admin_fingerprint()

    if admin_email or admin_fp:
        _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text="❌ Admin is already set. Use `set_admin.py` on the server to change."))
        return

    contact = bot.rpc.get_contact(accid, msg.from_id)
    email = contact.address
    database.set_config("admin_dc_email", email)

    fp = _get_contact_fingerprint(bot, accid, msg.from_id, contact=contact)
    if fp:
        first_fp = fp.split(',')[0]
        database.set_admin_fingerprint(first_fp)
        _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(
            text=f"✅ You are now the admin!\n\nEmail: `{email}`\nFingerprint: `{first_fp[-8:]}`"
        ))
    else:
        _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(
            text=f"✅ You are now the admin!\n\nEmail: `{email}`\n⚠️ Fingerprint not available yet (will be used after key exchange)."
        ))

@dc_cli.on(events.NewMessage(command="/url"))
def url_command(bot, accid, event):
    msg = event.msg
    if not _is_dc_admin(bot, accid, msg.from_id):
        _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text="❌ This command is only for the administrator."))
        return
        
    payload = event.payload.strip()
    if not payload:
        current_url = database.get_config("base_url") or "Not set"
        _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text=f"🔗 Base external status URL: `{current_url}`"))
        return
        
    # Standardize URL
    url = payload.rstrip('/')
    if not url.startswith("http://") and not url.startswith("https://"):
        _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text="❌ URL must start with http:// or https://"))
        return
        
    database.set_config("base_url", url)
    _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text=f"✅ Base status URL set to: `{url}`"))

@dc_cli.on(events.NewMessage(command="/add"))
def add_command(bot, accid, event):
    msg = event.msg
    payload = event.payload.strip()
    
    if not payload:
        _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(
            text="Usage: /add <target> [name]\n\nExamples:\n"
                 "• `/add https://google.com Google` (HTTP)\n"
                 "• `/add google.com:443 Google TCP` (TCP)\n"
                 "• `/add google.com Google Ping` (Ping)"
        ))
        return
        
    parts = payload.split(None, 1)
    target = parts[0]
    name = parts[1] if len(parts) > 1 else target
    
    try:
        check_type, url = parse_target(target)
    except ValueError as e:
        _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text=f"❌ {e}"))
        return
        
    res_id = database.add_resource(msg.chat_id, url, name, check_type)
    if res_id is None:
        _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text="❌ This target is already being monitored in this chat."))
        return
        
    _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(
        text=f"✅ Added monitor (ID: `{res_id}`):\n"
             f"🖥️ Name: **{name}**\n"
             f"🔗 Target: `{url}`\n"
             f"⚙️ Type: `{check_type.upper()}`\n"
             f"🕒 Checking once a minute."
    ))

@dc_cli.on(events.NewMessage(command="/remove"))
@dc_cli.on(events.NewMessage(command="/delete"))
def remove_command(bot, accid, event):
    msg = event.msg
    payload = event.payload.strip()
    if not payload or not payload.isdigit():
        _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text="Usage: /remove <id>"))
        return
        
    res_id = int(payload)
    if database.delete_resource(msg.chat_id, res_id):
        _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text=f"✅ Removed monitor with ID `{res_id}`."))
    else:
        _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text=f"❌ Monitor ID `{res_id}` not found in this chat."))

@dc_cli.on(events.NewMessage(command="/list"))
def list_command(bot, accid, event):
    msg = event.msg
    resources = database.get_resources(msg.chat_id)
    if not resources:
        _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text="ℹ️ No monitored resources in this chat. Add one with `/add <target>`."))
        return
        
    reply = "⚙️ **Monitored Resources:**\n\n"
    for r in resources:
        emoji_status = "🟢" if r["status"] == "up" else ("🔴" if r["status"] == "down" else "⚪")
        uptime = database.get_resource_uptime_30d(r["id"])
        reply += (
            f"{emoji_status} `ID: {r['id']}` **{r['name']}**\n"
            f"  Target: `{r['url']}` ({r['type'].upper()})\n"
            f"  Uptime 30d: `{uptime:.2f}%` | Status: `{r['status'].upper()}`\n\n"
        )
    _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text=reply))

@dc_cli.on(events.NewMessage(command="/status"))
def status_command(bot, accid, event):
    msg = event.msg
    resources = database.get_resources(msg.chat_id)
    if not resources:
        _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text="ℹ️ No resources monitored in this chat."))
        return
        
    total_monitors = len(resources)
    up_monitors = sum(1 for r in resources if r["status"] == "up")
    down_monitors = sum(1 for r in resources if r["status"] == "down")
    
    uptimes = [database.get_resource_uptime_30d(r["id"]) for r in resources]
    avg_uptime = sum(uptimes) / len(uptimes)
    
    token = database.get_or_create_chat_token(msg.chat_id)
    base_url = database.get_config("base_url") or "http://localhost:8080"
    status_page_url = f"{base_url}/{token}"
    
    reply = (
        f"📊 **Uptime Status Report (Last 30 days):**\n\n"
        f"📈 Overall Uptime: `{avg_uptime:.2f}%`\n"
        f"🖥️ Total Monitors: `{total_monitors}`\n"
        f"🟢 Online: `{up_monitors}` | 🔴 Offline: `{down_monitors}`\n\n"
        f"🔗 **Web Status Dashboard:**\n"
        f"{status_page_url}"
    )
    if not database.get_config("base_url"):
        reply += "\n\n💡 _Admin: Configure base URL via `/url https://domain` to get public links._"
        
    _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text=reply))

# Admin-Only Account and Transport Command handlers (Standard across bots)
@dc_cli.on(events.NewMessage(command="/accounts"))
def accounts_command(bot, accid, event):
    msg = event.msg
    if not _is_dc_admin(bot, accid, msg.from_id):
        _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text="❌ This command is only for the administrator."))
        return
    accids = bot.rpc.get_all_account_ids()
    reply = "🤖 **Configured Delta Chat Accounts:**\n\n"
    for a_id in accids:
        try:
            addr = bot.rpc.get_config(a_id, "addr")
            primary = " (Primary)" if a_id == accid else ""
            reply += f"• ID: `{a_id}` - `{addr}`{primary}\n"
        except Exception:
            pass
    _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text=reply))

@dc_cli.on(events.NewMessage(command="/rmaccount"))
def rmaccount_command(bot, accid, event):
    msg = event.msg
    if not _is_dc_admin(bot, accid, msg.from_id):
        _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text="❌ This command is only for the administrator."))
        return
    payload = event.payload.strip()
    if not payload or not payload.isdigit():
        _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text="Usage: /rmaccount <id>"))
        return
    target_id = int(payload)
    if target_id == accid:
        _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text="❌ Cannot delete the active account."))
        return
    try:
        bot.rpc.remove_account(target_id)
        _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text=f"✅ Account `{target_id}` deleted."))
    except Exception as e:
        _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text=f"❌ Failed to delete account: {e}"))

@dc_cli.on(events.NewMessage(command="/transports"))
def transports_command(bot, accid, event):
    msg = event.msg
    if not _is_dc_admin(bot, accid, msg.from_id):
        _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text="❌ This command is only for the administrator."))
        return
    
    try:
        transports = bot.rpc.list_transports(accid)
    except Exception:
        transports = []
        
    primary_addr = bot.rpc.get_config(accid, "configured_addr") or bot.rpc.get_config(accid, "addr")
    
    stats_map = {s["addr"]: s for s in database.get_all_transport_stats()}
    
    reply = "✉️ **Configured Mail Relays (Transports):**\n\n"
    for i, t in enumerate(transports):
        addr = t.get('addr', '') if isinstance(t, dict) else getattr(t, 'addr', '')
        status = "Active/Primary" if addr == primary_addr else "Backup"
        stats = stats_map.get(addr, {"msgs_sent": 0, "msgs_received": 0})
        
        reply += f"{i+1}. `{addr}` ({status})\n"
        reply += f"   📤 Sent: {stats.get('msgs_sent', 0)} | 📥 Received: {stats.get('msgs_received', 0)}\n"
        reply += "\n"
        
    reply += f"Total transports: {len(transports)}"
    _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text=reply))

@dc_cli.on(events.NewMessage(command="/addtransport"))
def addtransport_command(bot, accid, event):
    msg = event.msg
    if not _is_dc_admin(bot, accid, msg.from_id):
        _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text="❌ This command is only for the administrator."))
        return

    payload = event.payload.strip()
    if not payload:
        _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(
            text="Usage:\n"
                 "/addtransport DCACCOUNT:server.example\n"
                 "/addtransport user@example.com password123"
        ))
        return

    try:
        if payload.startswith("DCACCOUNT:"):
            bot.rpc.add_transport_from_qr(accid, payload)
            _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text="✅ Backup transport added via chatmail URI."))
        else:
            parts = payload.split(None, 1)
            if len(parts) < 2:
                _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(
                    text="❌ For email accounts, provide both address and password:\n"
                         "/addtransport user@example.com password123"
                ))
                return
            addr, password = parts[0], parts[1]
            bot.rpc.add_or_update_transport(accid, {"addr": addr, "password": password})
            _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text=f"✅ Backup transport `{addr}` added."))
    except Exception as e:
        _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text=f"❌ Failed to add transport: {e}"))

@dc_cli.on(events.NewMessage(command="/rmtransport"))
def rmtransport_command(bot, accid, event):
    msg = event.msg
    if not _is_dc_admin(bot, accid, msg.from_id):
        _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text="❌ This command is only for the administrator."))
        return

    addr = event.payload.strip()
    if not addr:
        _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text="Usage: /rmtransport user@example.com"))
        return

    try:
        transports = bot.rpc.list_transports(accid)
        transport_addrs = [t.get('addr', '') if isinstance(t, dict) else getattr(t, 'addr', '') for t in transports]
        if len(transport_addrs) <= 1:
            _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text="❌ Cannot remove the last transport. Add another one first."))
            return
        if addr not in transport_addrs:
            _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text=f"❌ Transport `{addr}` not found."))
            return
            
        bot.rpc.delete_transport(accid, addr)
        _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text=f"✅ Transport `{addr}` removed."))
    except Exception as e:
        _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text=f"❌ Failed to remove transport: {e}"))

@dc_cli.on(events.NewMessage(command="/setprimary"))
def setprimary_command(bot, accid, event):
    msg = event.msg
    if not _is_dc_admin(bot, accid, msg.from_id):
        _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text="❌ This command is only for the administrator."))
        return

    addr = event.payload.strip()
    if not addr:
        _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text="Usage: /setprimary user@example.com"))
        return

    try:
        transports = bot.rpc.list_transports(accid)
        transport_addrs = [t.get('addr', '') if isinstance(t, dict) else getattr(t, 'addr', '') for t in transports]
        if addr not in transport_addrs:
            _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text=f"❌ Transport `{addr}` not found."))
            return
            
        bot.rpc.set_config(accid, "configured_addr", addr)
        _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text=f"✅ Primary SMTP transport switched to `{addr}`."))
    except Exception as e:
        _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text=f"❌ Failed to set primary transport: {e}"))

@dc_cli.on(events.NewMessage(command="/resilient"))
def resilient_command(bot, accid, event):
    msg = event.msg
    if not _is_dc_admin(bot, accid, msg.from_id):
        _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text="❌ This command is only for the administrator."))
        return
    resilient = database.get_config("resilient_mode") == "1"
    new_state = "0" if resilient else "1"
    database.set_config("resilient_mode", new_state)
    state_str = "ENABLED" if new_state == "1" else "DISABLED"
    _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text=f"🔄 Resilient sending mode is now {state_str}."))

# Multi-transport resilient sending implementation
@dc_cli.on(events.RawEvent(events.EventType.MSG_FAILED))
def on_message_failed(bot, accid, event):
    if database.get_config("resilient_mode") != "1":
        return
        
    msg_id = event.msg_id
    logger.warning(f"RawEvent: Message fail detected for ID {msg_id}. Triggering failover check.")
    
    try:
        transports = bot.rpc.list_transports(accid)
        if len(transports) <= 1:
            return
            
        initial_addr = bot.rpc.get_config(accid, "configured_addr") or bot.rpc.get_config(accid, "addr")
        
        def bg_resend_worker(m_id, init_addr, t_list):
            time.sleep(5)
            for t in t_list:
                t_addr = t.get('addr', '') if isinstance(t, dict) else getattr(t, 'addr', '')
                if t_addr == init_addr:
                    continue
                try:
                    logger.info(f"Resilient send bg: switching primary transport to {t_addr}")
                    bot.rpc.set_config(accid, "configured_addr", t_addr)
                    time.sleep(2)
                    logger.info(f"Resilient send bg: resending msg {m_id} on transport {t_addr}...")
                    bot.rpc.resend_msg(accid, m_id)
                    database.increment_transport_sent(t_addr)
                    break
                except Exception as err:
                    logger.error(f"Resilient send bg: failed on transport {t_addr}: {err}")
            try:
                bot.rpc.set_config(accid, "configured_addr", init_addr)
            except Exception as restore_err:
                logger.error(f"Resilient send bg: failed to restore initial transport {init_addr}: {restore_err}")
                
        threading.Thread(target=bg_resend_worker, args=(msg_id, initial_addr, transports), daemon=True).start()
    except Exception as e:
        logger.error(f"Failover trigger error: {e}")

@dc_cli.on_init
def on_init(bot, args):
    setup_custom_command_parser(bot, ALLOWED_PREFIXES)
    
    global dc_bot_instance, dc_accid
    dc_bot_instance = bot
    
    for accid in bot.rpc.get_all_account_ids():
        dc_accid = accid
        try:
            bot.rpc.set_config(accid, "displayname", "Delta Chat Uptime Bot")
            bot.rpc.set_config(accid, "selfstatus", "Monitors resource availability (HTTP, TCP, Ping) and alerts on outages: https://github.com/mrgluek/deltachat_uptime")
            
            # Set bot avatar if icon file exists
            base_dir = os.path.dirname(os.path.abspath(__file__))
            for icon_name in ["icon.jpg", "icon.png"]:
                icon_path = os.path.join(base_dir, icon_name)
                if os.path.exists(icon_path):
                    bot.rpc.set_config(accid, "selfavatar", icon_path)
                    bot.logger.info(f"Avatar set from {icon_path}")
                    break
            else:
                bot.logger.warning(f"No icon.jpg or icon.png found in {base_dir}")
        except Exception as e:
            bot.logger.warning(f"Could not configure profile: {e}")
            
    # Start web server thread
    web_thread = threading.Thread(target=start_web_server_thread, daemon=True)
    web_thread.start()
    
    # Start monitoring check thread
    monitor_thread = threading.Thread(target=start_monitoring_thread, daemon=True)
    monitor_thread.start()

@dc_cli.on_start
def on_start(bot, _args):
    global dc_bot_instance, dc_accid
    dc_bot_instance = bot
    accounts = bot.rpc.get_all_account_ids()
    if accounts:
        dc_accid = accounts[0]
        try:
            bot.rpc.set_config(dc_accid, "download_limit", "1")
            bot.rpc.set_config(dc_accid, "delete_device_after", "86400")
            logger.info("Successfully set auto-download limit to 1 byte to optimize storage.")
        except Exception as e:
            logger.error(f"Failed to set storage optimizations: {e}")
            
        admin_email = database.get_config("admin_dc_email")
        admin_fp = database.get_admin_fingerprint()
        if admin_email:
            fp_suffix = f" ({admin_fp[-8:].upper()})" if admin_fp else ""
            print(f"Bot Administrator: {admin_email}{fp_suffix}")
            
        try:
            transports = bot.rpc.list_transports(dc_accid)
            print("\n" + "=" * 50)
            print("Configured Bot Transports (Relays):")
            for t in transports:
                addr = t.get('addr', '') if isinstance(t, dict) else getattr(t, 'addr', '')
                print(f" - {addr}")
        except Exception:
            pass

        try:
            qrdata = bot.rpc.get_chat_securejoin_qr_code(dc_accid, None)
            print("\nTo add this bot, scan the secure join QR code or copy the link below:\n")
            print(qrdata)
            print("\n" + "=" * 50 + "\n")
        except Exception:
            pass

@dc_cli.on(events.NewMessage)
def on_new_message(bot, accid, event):
    msg = event.msg
    if msg.is_info:
        return
        
    try:
        addr = bot.rpc.get_config(accid, "configured_addr") or bot.rpc.get_config(accid, "addr")
        if addr:
            database.increment_transport_received(addr)
    except Exception:
        pass

    text = (msg.text or "").strip()
    
    # Auto-greet new users in private chat
    try:
        chat_info = bot.rpc.get_basic_chat_info(accid, msg.chat_id)
        is_private = False
        if isinstance(chat_info, dict):
            is_private = (chat_info.get("type") == 1)
        else:
            is_private = (getattr(chat_info, "type", 1) == 1)
            
        if is_private:
            greeted_key = f"greeted_{msg.from_id}"
            if not database.get_config(greeted_key):
                help_command(bot, accid, event)
                database.set_config(greeted_key, "1")
    except Exception as e:
        logger.error(f"Error in greeting check: {e}")

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 2 and sys.argv[1] == "init" and sys.argv[2] == "transport":
        if len(sys.argv) < 4:
            print("Usage:")
            print("  python bot.py init transport DCACCOUNT:uri")
            print("  python bot.py init transport addr password")
            sys.exit(1)
            
        from deltachat2 import Rpc, IOTransport
        from appdirs import user_config_dir
        
        config_dir = user_config_dir("uptimebot")
        accounts_dir = os.path.join(config_dir, "accounts")
        
        try:
            with IOTransport(accounts_dir=accounts_dir) as trans:
                rpc = Rpc(trans)
                accids = rpc.get_all_account_ids()
                if not accids:
                    print("Error: No accounts configured. Run 'python bot.py init addr password' first.")
                    sys.exit(1)
                accid = accids[0]
                
                payload = sys.argv[3]
                if payload.startswith("DCACCOUNT:"):
                    rpc.add_transport_from_qr(accid, payload)
                    print(f"Success: Backup transport added via chatmail URI.")
                elif len(sys.argv) >= 5:
                    addr, password = sys.argv[3], sys.argv[4]
                    rpc.add_or_update_transport(accid, {"addr": addr, "password": password})
                    print(f"Success: Backup transport {addr} added.")
                else:
                    print("Error: For email accounts, provide both address and password.")
                    sys.exit(1)
        except Exception as e:
            print(f"Error adding transport: {e}")
            sys.exit(1)
        sys.exit(0)

    if len(sys.argv) == 1:
        sys.argv.append("serve")
    dc_cli.start()

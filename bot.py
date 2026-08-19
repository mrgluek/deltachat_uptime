import asyncio
import io
import logging
import json
import os
import ssl
import threading
import time
import datetime
import html
import re
import socket
from urllib.parse import urlparse
import aiohttp
from aiohttp import web
from deltachat2 import events, MsgData
from deltabot_cli import BotCli

import database

# Initialize logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("uptime_bot")
VERSION = "1.6.0"
USER_AGENT = f"DeltaChat-Uptime-Bot/{VERSION} (https://git.gluek.info/gluek/deltachat_uptime)"

dc_cli = BotCli("uptimebot")
bot_qr_cache = {}
last_sync_times = {}

# Global references
dc_bot_instance = None
dc_accid = None

# Canary targets for verifying host outbound internet connectivity
CANARY_TARGETS = [
    ("1.1.1.1", 53),
    ("8.8.8.8", 53),
    ("9.9.9.9", 53),
    ("1.0.0.1", 53),
]
_canary_cache_lock = asyncio.Lock()
_canary_last_checked = 0.0
_canary_last_result = True
_host_outage_active = False

async def _test_single_canary(host: str, port: int, timeout: float) -> bool:
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=timeout
        )
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return True
    except Exception:
        return False

async def check_host_internet_connectivity(timeout: float = 2.5, max_age: float = 5.0) -> bool:
    """Verifies that the bot host has outbound internet connectivity via fast canary checks."""
    global _canary_last_checked, _canary_last_result, _host_outage_active
    now = time.time()
    
    if now - _canary_last_checked < max_age:
        return _canary_last_result
        
    async with _canary_cache_lock:
        if time.time() - _canary_last_checked < max_age:
            return _canary_last_result
            
        tasks = [_test_single_canary(host, port, timeout) for host, port in CANARY_TARGETS]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        is_online = any(r is True for r in results)
        
        _canary_last_checked = time.time()
        _canary_last_result = is_online
        
        if not is_online:
            if not _host_outage_active:
                logger.warning("Host network outage detected! Canary checks failed. Suppressing false DOWN alerts.")
                _host_outage_active = True
        else:
            if _host_outage_active:
                logger.info("Host network connectivity restored.")
                _host_outage_active = False
                
        return is_online

# Async event loop and task tracking for check scheduler
async_event_loop = None
running_resource_ids = set()
running_lock = asyncio.Lock()
index_page_html_cache = None

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
                    chat_info = bot.rpc.get_basic_chat_info(accid, event.msg.chat_id)
                    if isinstance(chat_info, dict):
                        chat_type = chat_info.get('chat_type', 'Single')
                    else:
                        chat_type = getattr(chat_info, 'chat_type', 'Single')
                    is_group = str(chat_type) in ("Group", "Mailinglist", "OutBroadcast", "InBroadcast")
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
                            is_bot = c.get('is_bot', False) if isinstance(c, dict) else getattr(c, 'is_bot', False)
                            if is_bot:
                                bot_count += 1
                                if bot_count > 1:
                                    break
                        if bot_count > 1:
                            event.command = ""
                            event.payload = ""
                    except Exception:
                        pass

    bot._parse_command = custom_parse_command

def is_group_chat(chat) -> bool:
    if isinstance(chat, dict):
        t = chat.get("type")
        if t is not None:
            return t != 1
        ct = chat.get("chat_type")
        if ct is not None:
            return str(ct) != "Single"
        return False
    else:
        t = getattr(chat, "type", None)
        if t is not None:
            return t != 1
        ct = getattr(chat, "chat_type", "Single")
        return str(ct) != "Single"

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
async def check_ssl_expiry(url: str, timeout: float = 10.0) -> tuple[int | None, str | None]:
    """
    Connects to the HTTPS host, fetches peer certificate and returns:
    (expiry_timestamp_epoch, None) on success, or (None, error_str) on failure.
    """
    try:
        parsed = urlparse(url)
        host = parsed.hostname
        port = parsed.port or 443
        if not host:
            return None, "Invalid hostname"
            
        ctx = ssl.create_default_context()
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=ctx, server_hostname=host),
            timeout=timeout
        )
        ssl_obj = writer.get_extra_info("ssl_object")
        cert = ssl_obj.getpeercert() if ssl_obj else None
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass

        if not cert or "notAfter" not in cert:
            return None, "No certificate found"

        not_after_str = cert["notAfter"]
        try:
            exp_date = datetime.datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
        except ValueError:
            # Fallback in case of variant date formats
            import email.utils
            exp_date = email.utils.parsedate_to_datetime(not_after_str)
        exp_date = exp_date.replace(tzinfo=datetime.timezone.utc)
        return int(exp_date.timestamp()), None
    except ssl.SSLCertVerificationError as e:
        return None, f"SSL verification error: {getattr(e, 'verify_message', str(e))}"
    except ssl.SSLError as e:
        return None, f"SSL error: {e}"
    except asyncio.TimeoutError:
        return None, "SSL check timeout"
    except Exception as e:
        return None, f"SSL check error: {e}"

async def notify_ssl_alert(resource, days_left: float, exp_date_str: str, alert_stage: int):
    res_id = resource["id"]
    name = resource["name"] or resource["url"]
    url = resource["url"]
    chat_id = resource["dc_chat_id"]

    if alert_stage == -1:
        msg_text = (
            f"🚨 `ID: {res_id}` **{name}**\n"
            f"  Target: `{url}`\n"
            f"  🔒 **SSL Certificate Expired!** Expired on `{exp_date_str}`.\n"
            f"  Please renew the certificate immediately to restore secure access."
        )
    elif alert_stage == 1:
        hours_left = max(1, int(days_left * 24))
        msg_text = (
            f"🚨 `ID: {res_id}` **{name}**\n"
            f"  Target: `{url}`\n"
            f"  🔒 **SSL Certificate Expiration Warning (24 Hours)**\n"
            f"  Certificate will expire in ~`{hours_left}h` (on `{exp_date_str}`).\n"
            f"  Urgent: Please renew your SSL certificate now!"
        )
    elif alert_stage == 3:
        msg_text = (
            f"⚠️ `ID: {res_id}` **{name}**\n"
            f"  Target: `{url}`\n"
            f"  🔒 **SSL Certificate Expiration Warning (3 Days)**\n"
            f"  Certificate will expire in ~3 days (on `{exp_date_str}`).\n"
            f"  Please renew your SSL certificate soon."
        )
    elif alert_stage == 7:
        msg_text = (
            f"⚠️ `ID: {res_id}` **{name}**\n"
            f"  Target: `{url}`\n"
            f"  🔒 **SSL Certificate Expiration Warning (7 Days)**\n"
            f"  Certificate will expire in ~7 days (on `{exp_date_str}`).\n"
            f"  Please make sure your renewal automation or certificate is up to date."
        )
    else:
        return

    if dc_bot_instance and dc_accid is not None:
        try:
            await asyncio.to_thread(
                dc_bot_instance.rpc.send_msg,
                dc_accid,
                chat_id,
                MsgData(text=msg_text)
            )
        except Exception as e:
            logger.error(f"Failed to send SSL alert to chat {chat_id}: {e}")

async def run_single_check(resource) -> tuple[bool, str]:
    import http
    rtype = resource["type"]
    url = resource["url"]
    timeout = 10
    
    start_time = time.time()
    try:
        if rtype == "http":
            headers = {"User-Agent": USER_AGENT}
            async with aiohttp.ClientSession(headers=headers, timeout=aiohttp.ClientTimeout(total=timeout)) as session:
                async with session.get(url, allow_redirects=True) as resp:
                    try:
                        phrase = http.HTTPStatus(resp.status).phrase
                    except ValueError:
                        phrase = "Unknown Status"
                    details = f"{resp.status} - {phrase}"
                    if 200 <= resp.status < 400:
                        return True, details
                    else:
                        return False, details
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
            elapsed_ms = int((time.time() - start_time) * 1000)
            return True, f"{elapsed_ms} ms"
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
                elapsed_ms = int((time.time() - start_time) * 1000)
                return True, f"{elapsed_ms} ms"
            else:
                return False, "Ping failed"
    except asyncio.TimeoutError:
        return False, "Timeout"
    except Exception as e:
        return False, str(e)
    return False, "Unknown error"

async def check_group_task(group, semaphore):
    rep = group[0]
    async with semaphore:
        is_up, error_msg = await run_single_check(rep)
        
        # Retry logic: retry if check failed and at least one resource in the group was not already DOWN
        if not is_up and any(r["status"] != "down" for r in group):
            for retry in range(1, 3):
                for r in group:
                    if r["status"] != "down":
                        logger.info(f"Retry {retry}/2 for resource {r['id']} ({r['name'] or r['url']}) in chat {r['dc_chat_id']}")
                await asyncio.sleep(30)
                is_up, error_msg = await run_single_check(rep)
                if is_up:
                    break

        # Host Outage Protection: If check failed, verify host internet before marking DOWN
        if not is_up:
            has_internet = await check_host_internet_connectivity()
            if not has_internet:
                logger.warning(
                    f"Host internet outage detected! Suppressing DOWN check result for {rep['name'] or rep['url']} in chat {rep['dc_chat_id']}"
                )
                return
                    
        for r in group:
            logger.info(f"Check result: {r['name'] or r['url']} (id: {r['id']}) in chat {r['dc_chat_id']} -> {'UP' if is_up else 'DOWN'} ({error_msg})")
            await handle_check_result(r, is_up, error_msg)

        # Check SSL Certificate Expiry for HTTPS targets (at most once per hour)
        if rep.get("type") == "http" and rep.get("url", "").startswith("https://"):
            now = int(time.time())
            ssl_last_checked = rep.get("ssl_last_checked") or 0
            if now - ssl_last_checked >= 3600:
                ssl_exp_ts, ssl_err = await check_ssl_expiry(rep["url"])
                for r in group:
                    cur_state = r.get("ssl_alert_state") if r.get("ssl_alert_state") is not None else 0
                    new_state = cur_state
                    if ssl_exp_ts is not None:
                        days_left = (ssl_exp_ts - now) / 86400.0
                        exp_date_str = datetime.datetime.fromtimestamp(ssl_exp_ts, tz=datetime.timezone.utc).strftime('%Y-%m-%d')
                        
                        if days_left > 7:
                            if cur_state != 0:
                                new_state = 0
                        elif days_left <= 0:
                            if cur_state != -1:
                                new_state = -1
                                await notify_ssl_alert(r, days_left, exp_date_str, alert_stage=-1)
                        elif days_left <= 1:
                            if cur_state in (0, 7, 3):
                                new_state = 1
                                await notify_ssl_alert(r, days_left, exp_date_str, alert_stage=1)
                        elif days_left <= 3:
                            if cur_state in (0, 7):
                                new_state = 3
                                await notify_ssl_alert(r, days_left, exp_date_str, alert_stage=3)
                        elif days_left <= 7:
                            if cur_state == 0:
                                new_state = 7
                                await notify_ssl_alert(r, days_left, exp_date_str, alert_stage=7)
                                
                        await asyncio.to_thread(database.update_resource_ssl, r["id"], ssl_exp_ts, now, new_state)
                    else:
                        logger.warning(f"SSL check for {rep['url']} failed: {ssl_err}")
                        await asyncio.to_thread(database.update_resource_ssl, r["id"], r.get("ssl_expiry_date"), now, cur_state)

def format_incident_message(incident_id: int, started_at: int, resources: list[dict], is_resolved: bool = False, resolved_at: int = None) -> str:
    start_dt = datetime.datetime.fromtimestamp(started_at, tz=datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
    now = int(time.time())
    
    total_monitors = len(resources)
    down_resources = [r for r in resources if r.get("status") == "down"]
    up_resources = [r for r in resources if r.get("status") == "up"]
    
    if is_resolved:
        resolved_ts = resolved_at or now
        resolved_dt = datetime.datetime.fromtimestamp(resolved_ts, tz=datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
        duration = max(1, resolved_ts - started_at)
        duration_str = format_duration(duration)
        
        lines = [
            f"✅ **Incident #{incident_id}** — `Resolved`",
            f"⏱ **Duration:** `{duration_str}` (`{start_dt}` → `{resolved_dt} UTC`)",
            f"📊 **All {total_monitors} monitors operational**\n"
        ]
        for r in resources:
            r_name = r.get("name") or r.get("url")
            r_type = r.get("type", "HTTP").upper()
            uptime_val = database.get_resource_uptime_30d(r["id"])
            lines.append(f"• 🟢 `ID: {r['id']}` **{r_name}** ({r_type}) — Uptime 30d: `{uptime_val:.2f}%`")
        return "\n".join(lines)
        
    else:
        duration = max(1, now - started_at)
        duration_str = format_duration(duration)
        down_count = len(down_resources)
        
        # Check if partially recovered
        partially_recovered = any((r.get("last_changed") or 0) >= started_at for r in up_resources) and down_count > 0 and len(up_resources) > 0
        
        if partially_recovered:
            status_tag = "Ongoing (Partial Recovery)"
            header_icon = "⚠️"
        else:
            status_tag = "Ongoing"
            header_icon = "🚨"
            
        lines = [
            f"{header_icon} **Incident #{incident_id}** — `{status_tag}`",
            f"⏱ **Started:** `{start_dt} UTC` (active for `{duration_str}`)",
            f"📊 **Affected:** {down_count} / {total_monitors} monitors down\n",
            "**Current Status:**"
        ]
        
        for r in down_resources:
            r_name = r.get("name") or r.get("url")
            r_type = r.get("type", "HTTP").upper()
            d_time = max(1, now - (r.get("last_changed") or started_at))
            d_str = format_duration(d_time)
            uptime_val = database.get_resource_uptime_30d(r["id"])
            lines.append(f"• 🔴 `ID: {r['id']}` **{r_name}**\n  Target: `{r['url']}` ({r_type})\n  Status: `DOWN` (down for `{d_str}`) | Uptime 30d: `{uptime_val:.2f}%`")
            
        for r in up_resources:
            if (r.get("last_changed") or 0) >= started_at:
                r_name = r.get("name") or r.get("url")
                r_type = r.get("type", "HTTP").upper()
                rec_dt = datetime.datetime.fromtimestamp(r.get("last_changed"), tz=datetime.timezone.utc).strftime('%H:%M:%S')
                uptime_val = database.get_resource_uptime_30d(r["id"])
                lines.append(f"• 🟢 `ID: {r['id']}` **{r_name}**\n  Target: `{r['url']}` ({r_type})\n  Status: `UP` (recovered at `{rec_dt} UTC`) | Uptime 30d: `{uptime_val:.2f}%`")

        return "\n".join(lines)

_incident_sync_locks = {}
_incident_global_lock = asyncio.Lock()

async def get_chat_incident_lock(dc_chat_id: int) -> asyncio.Lock:
    async with _incident_global_lock:
        if dc_chat_id not in _incident_sync_locks:
            _incident_sync_locks[dc_chat_id] = asyncio.Lock()
        return _incident_sync_locks[dc_chat_id]

async def sync_chat_incident_state(dc_chat_id: int):
    chat_lock = await get_chat_incident_lock(dc_chat_id)
    async with chat_lock:
        resources = await asyncio.to_thread(database.get_resources, dc_chat_id)
        if not resources:
            return
            
        down_resources = [r for r in resources if r.get("status") == "down"]
        active_incident = await asyncio.to_thread(database.get_active_incident, dc_chat_id)
        now = int(time.time())
        
        if down_resources:
            if not active_incident:
                inc_id = await asyncio.to_thread(database.create_incident, dc_chat_id, now)
                active_incident = await asyncio.to_thread(database.get_incident_by_id, dc_chat_id, inc_id)
                
            msg_text = format_incident_message(
                active_incident["id"],
                active_incident["started_at"],
                resources,
                is_resolved=False
            )
            
            if dc_bot_instance and dc_accid is not None:
                msg_id = active_incident.get("msg_id")
                if msg_id:
                    try:
                        await asyncio.to_thread(
                            dc_bot_instance.rpc.send_edit_request,
                            dc_accid,
                            msg_id,
                            msg_text
                        )
                        logger.info(f"Edited Incident #{active_incident['id']} message {msg_id} in chat {dc_chat_id}")
                    except Exception as e:
                        logger.warning(f"Failed to edit Incident message {msg_id} (sending new message): {e}")
                        try:
                            new_msg_id = await asyncio.to_thread(
                                dc_bot_instance.rpc.send_msg,
                                dc_accid,
                                dc_chat_id,
                                MsgData(text=msg_text)
                            )
                            if new_msg_id:
                                await asyncio.to_thread(database.update_incident_msg_id, active_incident["id"], new_msg_id)
                        except Exception as ex:
                            logger.error(f"Failed to send incident message to chat {dc_chat_id}: {ex}")
                else:
                    try:
                        new_msg_id = await asyncio.to_thread(
                            dc_bot_instance.rpc.send_msg,
                            dc_accid,
                            dc_chat_id,
                            MsgData(text=msg_text)
                        )
                        if new_msg_id:
                            await asyncio.to_thread(database.update_incident_msg_id, active_incident["id"], new_msg_id)
                    except Exception as e:
                        logger.error(f"Failed to send incident message to chat {dc_chat_id}: {e}")
                        
        else:
            if active_incident:
                summary_str = f"All {len(resources)} monitors recovered"
                await asyncio.to_thread(database.resolve_incident, active_incident["id"], now, summary_str)
                
                msg_text = format_incident_message(
                    active_incident["id"],
                    active_incident["started_at"],
                    resources,
                    is_resolved=True,
                    resolved_at=now
                )
                
                if dc_bot_instance and dc_accid is not None:
                    msg_id = active_incident.get("msg_id")
                    if msg_id:
                        try:
                            await asyncio.to_thread(
                                dc_bot_instance.rpc.send_edit_request,
                                dc_accid,
                                msg_id,
                                msg_text
                            )
                            logger.info(f"Resolved Incident #{active_incident['id']} by editing message {msg_id} in chat {dc_chat_id}")
                        except Exception as e:
                            logger.warning(f"Failed to edit resolved Incident message {msg_id}: {e}")
                            try:
                                await asyncio.to_thread(
                                    dc_bot_instance.rpc.send_msg,
                                    dc_accid,
                                    dc_chat_id,
                                    MsgData(text=msg_text)
                                )
                            except Exception as ex:
                                logger.error(f"Failed to send resolved incident message to chat {dc_chat_id}: {ex}")

async def check_stale_downtime_notifications(resource, now: int):
    """Check for continuous prolonged downtime and send 7d notice, 14d warning, or execute 30d auto-cleanup."""
    res = await asyncio.to_thread(database.get_resource_by_id, resource["id"])
    if not res or res["status"] != "down":
        return

    last_changed = res.get("last_changed") or now
    down_duration = now - last_changed
    stale_level = res.get("stale_warning_level") or 0

    dc_chat_id = res["dc_chat_id"]
    res_id = res["id"]
    res_name = res.get("name") or res.get("url")
    res_url = res.get("url")

    # 30 Days (2,592,000s): Auto-cleanup and notify chat
    if down_duration >= 30 * 86400:
        logger.warning(f"Resource {res_id} ({res_name}) in chat {dc_chat_id} has been down for 30+ days. Auto-removing from monitoring...")
        await asyncio.to_thread(database.delete_resource, dc_chat_id, res_id)
        cleanup_text = (
            f"🗑️ **Auto-Cleanup (30 Days Unreachable)**\n\n"
            f"Resource **{res_name}** (`ID: {res_id}`) targeting `{res_url}` has had 0% uptime for **30 days** "
            f"and has been automatically removed from monitoring."
        )
        try:
            if dc_bot_instance and dc_accid:
                await asyncio.to_thread(
                    _dc_send_msg_with_stats,
                    dc_bot_instance,
                    dc_accid,
                    dc_chat_id,
                    MsgData(text=cleanup_text)
                )
        except Exception as ex:
            logger.error(f"Failed to send 30d auto-cleanup message to chat {dc_chat_id}: {ex}")
        await sync_chat_incident_state(dc_chat_id)
        return

    # 14 Days (1,209,600s): Warning before 30d auto-removal
    elif down_duration >= 14 * 86400 and stale_level < 14:
        await asyncio.to_thread(database.update_stale_warning_level, res_id, 14)
        warn_text = (
            f"⚠️ **Downtime Warning (14 Days Unreachable)**\n\n"
            f"Resource **{res_name}** (`ID: {res_id}`) targeting `{res_url}` has been continuously unreachable for **14 days**.\n\n"
            f"💡 _Please note: resources that remain at 0% uptime for **30 days** will be automatically removed from monitoring._ "
            f"You can remove it anytime using `/remove {res_id}`."
        )
        try:
            if dc_bot_instance and dc_accid:
                await asyncio.to_thread(
                    _dc_send_msg_with_stats,
                    dc_bot_instance,
                    dc_accid,
                    dc_chat_id,
                    MsgData(text=warn_text)
                )
        except Exception as ex:
            logger.error(f"Failed to send 14d warning message to chat {dc_chat_id}: {ex}")

    # 7 Days (604,800s): Notice to remove decommissioned services
    elif down_duration >= 7 * 86400 and stale_level < 7:
        await asyncio.to_thread(database.update_stale_warning_level, res_id, 7)
        notice_text = (
            f"⚠️ **Downtime Notice (7 Days Unreachable)**\n\n"
            f"Resource **{res_name}** (`ID: {res_id}`) targeting `{res_url}` has been continuously unreachable for **7 days**.\n\n"
            f"If this service has been permanently retired or decommissioned, consider removing it from monitoring with `/remove {res_id}`."
        )
        try:
            if dc_bot_instance and dc_accid:
                await asyncio.to_thread(
                    _dc_send_msg_with_stats,
                    dc_bot_instance,
                    dc_accid,
                    dc_chat_id,
                    MsgData(text=notice_text)
                )
        except Exception as ex:
            logger.error(f"Failed to send 7d notice message to chat {dc_chat_id}: {ex}")


async def handle_check_result(resource, is_up, error_msg):
    status = "up" if is_up else "down"
    old_status = resource["status"]
    now = int(time.time())
    
    failures = 0 if is_up else (resource["consecutive_failures"] + 1)
    await asyncio.to_thread(database.update_resource_status, resource["id"], status, failures, error_msg)
    
    should_sync = False
    if old_status != status:
        if old_status != "unknown" or status == "down":
            should_sync = True
            
    if should_sync:
        await sync_chat_incident_state(resource["dc_chat_id"])

    # If resource is down, evaluate 7d/14d/30d stale downtime reminders and auto-cleanup
    if not is_up:
        await check_stale_downtime_notifications(resource, now)

async def run_and_track_group(group, semaphore):
    try:
        await check_group_task(group, semaphore)
    finally:
        async with running_lock:
            for r in group:
                running_resource_ids.discard(r["id"])

async def run_checks_parallel(tasks_list):
    await asyncio.gather(*tasks_list, return_exceptions=True)

async def monitoring_scheduler_loop():
    import collections
    semaphore = asyncio.Semaphore(50)
    while True:
        try:
            # If host network outage was detected, verify connectivity before launching checks
            if _host_outage_active:
                is_online = await check_host_internet_connectivity(timeout=2.0, max_age=0.0)
                if not is_online:
                    logger.warning("Host network outage is still active. Pausing monitoring checks for 10 seconds...")
                    await asyncio.sleep(10)
                    continue

            resources = await asyncio.to_thread(database.get_all_resources)
            now = int(time.time())
            
            # Group due resources by (type, url)
            due_groups = collections.defaultdict(list)
            async with running_lock:
                for r in resources:
                    r_id = r["id"]
                    if r_id in running_resource_ids:
                        continue
                        
                    last_checked = r["last_checked"] or 0
                    interval = r["interval"] or 60
                    
                    if now - last_checked >= interval:
                        running_resource_ids.add(r_id)
                        target_key = (r["type"], r["url"])
                        due_groups[target_key].append(r)
            
            tasks = []
            for target_key, group in due_groups.items():
                tasks.append(run_and_track_group(group, semaphore))
                
            if tasks:
                logger.info(f"Triggering {len(tasks)} target checks (encompassing {sum(len(g) for g in due_groups.values())} resources)...")
                asyncio.create_task(run_checks_parallel(tasks))
                
        except Exception as e:
            logger.error(f"Error in monitoring scheduler loop: {e}")
            
        await asyncio.sleep(5)

# Web Server handling and dashboard HTML templates
def get_dashboard_html(chat_name, resources, overall_uptime, incidents=None) -> str:
    total_monitors = len(resources)
    up_monitors = sum(1 for r in resources if r["status"] == "up")
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
                
            ssl_stat_html = ""
            if r.get("url", "").startswith("https://"):
                exp_ts = r.get("ssl_expiry_date")
                if exp_ts:
                    now_ts = int(time.time())
                    d_left = int((exp_ts - now_ts) / 86400)
                    if d_left < 0:
                        ssl_color = "var(--color-down)"
                        ssl_txt = "Expired"
                    elif d_left <= 7:
                        ssl_color = "var(--color-warn)"
                        ssl_txt = f"{d_left}d left"
                    else:
                        ssl_color = "var(--color-up)"
                        ssl_txt = f"{d_left}d left"
                    ssl_stat_html = f"""
                    <div class="m-stat">
                        <span class="m-val" style="color: {ssl_color}; font-size: 0.875rem;">{ssl_txt}</span>
                        <span class="m-lbl">SSL Cert</span>
                    </div>
                    """
                else:
                    ssl_stat_html = """
                    <div class="m-stat">
                        <span class="m-val" style="color: var(--text-muted); font-size: 0.875rem;">Pending</span>
                        <span class="m-lbl">SSL Cert</span>
                    </div>
                    """
                
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
                    {ssl_stat_html}
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

    incidents_html = ""
    if incidents:
        inc_items = ""
        for inc in incidents:
            inc_id = inc["id"]
            inc_status = inc["status"]
            started_at = inc["started_at"]
            resolved_at = inc["resolved_at"]
            start_str = datetime.datetime.fromtimestamp(started_at, tz=datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
            
            if inc_status == "ongoing":
                d_str = format_duration(int(time.time()) - started_at)
                inc_items += f"""
                <div class="monitor-card" style="border-left: 4px solid var(--color-down);">
                    <div class="monitor-info">
                        <span class="indicator down"></span>
                        <div class="monitor-meta">
                            <span class="monitor-name" style="color: var(--color-down);">Incident #{inc_id} — Ongoing</span>
                            <span class="monitor-url">Started: {start_str} UTC (active for {d_str})</span>
                        </div>
                    </div>
                </div>
                """
            else:
                resolved_str = datetime.datetime.fromtimestamp(resolved_at, tz=datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S') if resolved_at else "Resolved"
                duration = max(1, (resolved_at or int(time.time())) - started_at)
                d_str = format_duration(duration)
                inc_items += f"""
                <div class="monitor-card" style="border-left: 4px solid var(--color-up);">
                    <div class="monitor-info">
                        <span class="indicator up"></span>
                        <div class="monitor-meta">
                            <span class="monitor-name">Incident #{inc_id} — Resolved</span>
                            <span class="monitor-url">{start_str} → {resolved_str} UTC ({d_str})</span>
                        </div>
                    </div>
                </div>
                """
        incidents_html = f"""
        <h3 class="monitors-title" style="margin-top: 2rem;">📋 Recent Incidents</h3>
        <div class="monitors-grid">
            {inc_items}
        </div>
        """
            
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Delta Chat Uptime Monitor - {html.escape(chat_name)}</title>
    <link rel="icon" type="image/png" href="/icon.png" />
    <link rel="shortcut icon" href="/favicon.ico" />
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
        :root {{
            --bg-primary: #0f172a;
            --bg-card: #1e293b;
            --bg-stat: rgba(30, 41, 59, 0.5);
            --border-color: #334155;
            --text-primary: #f8fafc;
            --text-muted: #94a3b8;
            --color-up: #10b981;
            --color-down: #ef4444;
            --color-warn: #f59e0b;
        }}
        
        * {{
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }}
        
        body {{
            font-family: 'Plus Jakarta Sans', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background-color: var(--bg-primary);
            color: var(--text-primary);
            min-height: 100vh;
            display: flex;
            flex-direction: column;
        }}
        
        header {{
            background: rgba(15, 23, 42, 0.8);
            backdrop-filter: blur(8px);
            border-bottom: 1px solid var(--border-color);
            padding: 1rem 1.5rem;
            position: sticky;
            top: 0;
            z-index: 10;
        }}
        
        .logo-container {{
            max-width: 1100px;
            margin: 0 auto;
            display: flex;
            align-items: center;
            gap: 0.75rem;
        }}
        
        .logo-img {{
            width: 32px;
            height: 32px;
            border-radius: 8px;
        }}
        
        .logo-title {{
            font-size: 1.25rem;
            font-weight: 700;
            background: linear-gradient(to right, #38bdf8, #818cf8);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }}
        
        main {{
            flex: 1;
            max-width: 1100px;
            width: 100%;
            margin: 0 auto;
            padding: 2rem 1.5rem;
        }}
        
        .stats-panel {{
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 16px;
            padding: 1.5rem;
            margin-bottom: 2rem;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06);
        }}
        
        .stats-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 1.5rem;
            flex-wrap: wrap;
            gap: 1rem;
        }}
        
        .stats-header h2 {{
            font-size: 1.5rem;
            font-weight: 700;
        }}
        
        .status-badge {{
            display: inline-flex;
            align-items: center;
            gap: 0.5rem;
            padding: 0.5rem 1rem;
            border-radius: 9999px;
            font-size: 0.875rem;
            font-weight: 600;
        }}
        
        .status-badge.all-up {{
            background: rgba(16, 185, 129, 0.1);
            color: var(--color-up);
            border: 1px solid rgba(16, 185, 129, 0.2);
        }}
        
        .status-badge.some-down {{
            background: rgba(239, 68, 68, 0.1);
            color: var(--color-down);
            border: 1px solid rgba(239, 68, 68, 0.2);
        }}
        
        .indicator {{
            width: 8px;
            height: 8px;
            border-radius: 50%;
            display: inline-block;
        }}
        
        .indicator.up {{
            background-color: var(--color-up);
            box-shadow: 0 0 8px var(--color-up);
        }}
        
        .indicator.down {{
            background-color: var(--color-down);
            box-shadow: 0 0 8px var(--color-down);
        }}
        
        .indicator.unknown {{
            background-color: var(--text-muted);
        }}
        
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 1rem;
        }}
        
        .stat-card {{
            background: var(--bg-stat);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 1rem;
            display: flex;
            flex-direction: column;
            gap: 0.25rem;
        }}
        
        .stat-val {{
            font-size: 1.5rem;
            font-weight: 700;
        }}
        
        .stat-lbl {{
            font-size: 0.75rem;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }}
        
        .monitors-title {{
            font-size: 1.25rem;
            font-weight: 600;
            margin-bottom: 1rem;
        }}
        
        .monitors-grid {{
            display: flex;
            flex-direction: column;
            gap: 0.75rem;
        }}
        
        .monitor-card {{
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 1.25rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 1rem;
            transition: border-color 0.2s;
        }}
        
        .monitor-card:hover {{
            border-color: #475569;
        }}
        
        .monitor-info {{
            display: flex;
            align-items: center;
            gap: 1rem;
        }}
        
        .monitor-meta {{
            display: flex;
            flex-direction: column;
            gap: 0.25rem;
        }}
        
        .monitor-name {{
            font-weight: 600;
            font-size: 1.05rem;
        }}
        
        .monitor-url {{
            font-size: 0.875rem;
            color: var(--text-muted);
            word-break: break-all;
        }}
        
        .monitor-type {{
            display: inline-block;
            font-size: 0.75rem;
            padding: 0.125rem 0.375rem;
            border-radius: 4px;
            text-transform: uppercase;
            font-weight: 600;
            color: var(--text-muted);
            border: 1px solid var(--border-color);
            background: rgba(255, 255, 255, 0.05);
            width: max-content;
        }}
        
        .monitor-stats {{
            display: flex;
            gap: 1.5rem;
            align-items: center;
        }}
        
        .m-stat {{
            display: flex;
            flex-direction: column;
            gap: 0.125rem;
        }}
        
        .m-val {{
            font-weight: 600;
        }}
        
        .m-lbl {{
            font-size: 0.7rem;
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
        }}
        
        footer a {{
            color: #38bdf8;
            text-decoration: none;
        }}
        
        footer a:hover {{
            text-decoration: underline;
        }}
        
        .empty-state {{
            text-align: center;
            padding: 3rem 1rem;
            color: var(--text-muted);
        }}
        
        .empty-icon {{
            font-size: 2.5rem;
            margin-bottom: 0.5rem;
        }}
    </style>
</head>
<body>
    <header>
        <div class="logo-container">
            <img class="logo-img" src="/icon.png" alt="Logo">
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
        {incidents_html}
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
    incidents = await asyncio.to_thread(database.get_recent_incidents, chat_id, 5)
    
    # Calculate average uptime
    overall_uptime = 100.0
    if resources:
        uptimes = []
        for r in resources:
            u = await asyncio.to_thread(database.get_resource_uptime_30d, r["id"])
            uptimes.append(u)
        overall_uptime = sum(uptimes) / len(uptimes)
        
    html_content = get_dashboard_html(chat_name, resources, overall_uptime, incidents)
    return web.Response(text=html_content, content_type="text/html")

async def handle_index(request):
    global index_page_html_cache
    if index_page_html_cache is None:
        index_page_html_cache = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Delta Chat Uptime Bot</title>
    <link rel="icon" type="image/png" href="/icon.png" />
    <link rel="shortcut icon" href="/favicon.ico" />
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;600;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-color: #0b0f19;
            --card-bg: rgba(20, 26, 42, 0.6);
            --border-color: rgba(255, 255, 255, 0.08);
            --text-main: #f3f4f6;
            --text-muted: #9ca3af;
            --color-up: #10b981;
            --color-primary: #3b82f6;
            --glow-primary: rgba(59, 130, 246, 0.4);
        }
        
        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }
        
        body {
            font-family: 'Outfit', sans-serif;
            background-color: var(--bg-color);
            color: var(--text-main);
            min-height: 100vh;
            display: flex;
            flex-direction: column;
            justify-content: space-between;
            background-image: 
                radial-gradient(circle at 10% 20%, rgba(59, 130, 246, 0.06) 0%, transparent 40%),
                radial-gradient(circle at 90% 80%, rgba(16, 185, 129, 0.05) 0%, transparent 40%);
        }
        
        header {
            padding: 2rem 1.5rem;
            max-width: 900px;
            width: 100%;
            margin: 0 auto;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .logo-container {
            display: flex;
            align-items: center;
            gap: 0.75rem;
        }
        
        .logo-img {
            width: 32px;
            height: 32px;
            border-radius: 6px;
            object-fit: cover;
        }
        
        .logo-title {
            font-size: 1.5rem;
            font-weight: 700;
            background: linear-gradient(135deg, #3b82f6, #10b981);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        
        main {
            flex-grow: 1;
            max-width: 900px;
            width: 100%;
            margin: 0 auto;
            padding: 0 1.5rem 3rem;
            display: flex;
            flex-direction: column;
            gap: 2.5rem;
        }
        
        .hero {
            text-align: center;
            padding: 2rem 0;
            display: flex;
            flex-direction: column;
            align-items: center;
            gap: 1rem;
        }
        
        .hero h1 {
            font-size: 2.5rem;
            font-weight: 700;
            line-height: 1.2;
            background: linear-gradient(135deg, #ffffff, #9ca3af);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        
        .hero p {
            font-size: 1.125rem;
            color: var(--text-muted);
            max-width: 600px;
        }
        
        .card {
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 1rem;
            padding: 2rem;
            backdrop-filter: blur(12px);
            position: relative;
            overflow: hidden;
        }
        
        .card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 3px;
            background: linear-gradient(90deg, #3b82f6, #10b981);
        }
        
        .card h2 {
            font-size: 1.5rem;
            font-weight: 600;
            margin-bottom: 1.25rem;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }
        
        .features-list {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
            gap: 1.5rem;
            margin-top: 0.5rem;
        }
        
        .feature-item {
            display: flex;
            gap: 0.75rem;
        }
        
        .feature-icon {
            font-size: 1.25rem;
            color: var(--color-up);
        }
        
        .feature-text h3 {
            font-size: 1.05rem;
            font-weight: 600;
            margin-bottom: 0.25rem;
        }
        
        .feature-text p {
            font-size: 0.9rem;
            color: var(--text-muted);
            line-height: 1.4;
        }
        
        .steps {
            display: flex;
            flex-direction: column;
            gap: 1rem;
        }
        
        .step-item {
            display: flex;
            gap: 1rem;
            align-items: flex-start;
        }
        
        .step-num {
            width: 28px;
            height: 28px;
            border-radius: 50%;
            background: rgba(59, 130, 246, 0.1);
            border: 1px solid rgba(59, 130, 246, 0.3);
            color: var(--color-primary);
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: 700;
            font-size: 0.9rem;
            flex-shrink: 0;
        }
        
        .step-content h3 {
            font-size: 1.05rem;
            font-weight: 600;
            margin-bottom: 0.25rem;
        }
        
        .step-content p {
            font-size: 0.9rem;
            color: var(--text-muted);
            line-height: 1.4;
        }
        
        .commands-table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 0.5rem;
        }
        
        .commands-table th, .commands-table td {
            text-align: left;
            padding: 0.75rem 1rem;
            border-bottom: 1px solid var(--border-color);
        }
        
        .commands-table th {
            color: var(--text-muted);
            font-size: 0.85rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            font-weight: 600;
        }
        
        .commands-table td code {
            background: rgba(255, 255, 255, 0.05);
            padding: 0.2rem 0.5rem;
            border-radius: 0.25rem;
            font-family: monospace;
            font-size: 0.9rem;
            color: #3b82f6;
        }
        
        .commands-table td {
            font-size: 0.95rem;
        }
        
        footer {
            padding: 2rem 1.5rem;
            text-align: center;
            font-size: 0.875rem;
            color: var(--text-muted);
            border-top: 1px solid var(--border-color);
            background: rgba(11, 15, 25, 0.8);
            margin-top: auto;
        }
        
        footer a {
            color: #3b82f6;
            text-decoration: none;
        }
        
        footer a:hover {
            text-decoration: underline;
        }
    </style>
</head>
<body>
    <header>
        <div class="logo-container">
            <img class="logo-img" src="/icon.png" alt="Logo">
            <span class="logo-title">Delta Chat Uptime</span>
        </div>
    </header>
    
    <main>
        <div class="hero">
            <h1>Delta Chat Uptime Monitor</h1>
            <p>A self-hosted, high-concurrency availability monitoring service that sends downtime alerts directly to Delta Chat and hosts beautiful status dashboards.</p>
        </div>
        
        <div class="card">
            <h2>✨ Key Features</h2>
            <div class="features-list">
                <div class="feature-item">
                    <span class="feature-icon">🛡️</span>
                    <div class="feature-text">
                        <h3>Secure Ownership</h3>
                        <p>Claim bot administration using cryptographic fingerprints to secure transports and configurations.</p>
                    </div>
                </div>
                <div class="feature-item">
                    <span class="feature-icon">💬</span>
                    <div class="feature-text">
                        <h3>Per-Chat Monitoring</h3>
                        <p>Monitors are scoped to individual group chats or private chats for privacy and organization.</p>
                    </div>
                </div>
                <div class="feature-item">
                    <span class="feature-icon">⚙️</span>
                    <div class="feature-text">
                        <h3>Multiple Check Modes</h3>
                        <p>Support HTTP/HTTPS availability, SSL/TLS certificate expiry checks, TCP ports, and non-blocking ICMP Pings.</p>
                    </div>
                </div>
                <div class="feature-item">
                    <span class="feature-icon">🔒</span>
                    <div class="feature-text">
                        <h3>SSL Certificate Alerts</h3>
                        <p>Tracks HTTPS certificate expiry with hourly checks and proactive notifications at 7d, 3d, and 24h.</p>
                    </div>
                </div>
                <div class="feature-item">
                    <span class="feature-icon">🔄</span>
                    <div class="feature-text">
                        <h3>Smart Retry Logic</h3>
                        <p>Retries 2 times (30s apart) on failures to avoid false alerts. Recovery is marked UP instantly.</p>
                    </div>
                </div>
            </div>
        </div>
        
        <div class="card">
            <h2>🚀 Getting Started</h2>
            <div class="steps">
                <div class="step-item">
                    <span class="step-num">1</span>
                    <div class="step-content">
                        <h3>Add Uptime Bot in Delta Chat</h3>
                        <p>Scan the bot's secure join QR code or add the bot's email address to start chatting.</p>
                    </div>
                </div>
                <div class="step-item">
                    <span class="step-num">2</span>
                    <div class="step-content">
                        <h3>Claim Admin Rights</h3>
                        <p>Send <code>/initadmin</code> in a private chat to link your profile securely via fingerprint authorization.</p>
                    </div>
                </div>
                <div class="step-item">
                    <span class="step-num">3</span>
                    <div class="step-content">
                        <h3>Start Monitoring</h3>
                        <p>Add your first resource with <code>/add https://yourwebsite.com "My Site"</code>. The bot will start periodic checks immediately!</p>
                    </div>
                </div>
            </div>
        </div>
        
        <div class="card">
            <h2>⌨️ Bot Commands</h2>
            <table class="commands-table">
                <thead>
                    <tr>
                        <th>Command</th>
                        <th>Description</th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td><code>/add &lt;target&gt; [name]</code></td>
                        <td>Add a website (HTTP), socket (IP:port) or host (Ping) to monitor.</td>
                    </tr>
                    <tr>
                        <td><code>/remove &lt;id&gt;</code></td>
                        <td>Stop monitoring a resource and delete it.</td>
                    </tr>
                    <tr>
                        <td><code>/list</code></td>
                        <td>List monitored targets and their current state in the current chat.</td>
                    </tr>
                    <tr>
                        <td><code>/status</code></td>
                        <td>Display average 30-day uptime and link to the secure web dashboard.</td>
                    </tr>
                    <tr>
                        <td><code>/help</code></td>
                        <td>Show instructions and bot version details.</td>
                    </tr>
                </tbody>
            </table>
        </div>
    </main>
    
    <footer>
        <p>Delta Chat Uptime Bot is open-source. Code on <a href="https://github.com/mrgluek/deltachat_uptime" target="_blank">GitHub</a> | <a href="https://git.gluek.info/gluek/deltachat_uptime" target="_blank">Forgejo Mirror</a></p>
    </footer>
</body>
</html>"""
    headers = {
        "Cache-Control": "public, max-age=3600"
    }
    return web.Response(text=index_page_html_cache, content_type="text/html", headers=headers)

async def handle_robots_txt(request):
    headers = {
        "Cache-Control": "public, max-age=86400"
    }
    content = "User-agent: *\nDisallow: /\n"
    return web.Response(text=content, content_type="text/plain", headers=headers)

async def handle_icon(request):
    filename = request.path.lstrip('/')
    if filename == 'favicon.ico':
        filename = 'icon.png'
        
    if os.path.exists(filename):
        headers = {
            'Cache-Control': 'public, max-age=31536000, immutable'
        }
        return web.FileResponse(filename, headers=headers)
    return web.Response(status=404)

async def _run_web_server():
    app = web.Application()
    app.router.add_get('/icon.png', handle_icon)
    app.router.add_get('/favicon.ico', handle_icon)
    app.router.add_get('/robots.txt', handle_robots_txt)
    app.router.add_get('/', handle_index)
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
        msg_id = bot.rpc.send_msg(accid, chat_id, msg_data)
        addr = bot.rpc.get_config(accid, "configured_addr") or bot.rpc.get_config(accid, "addr")
        if addr:
            database.increment_transport_sent(addr)
        return msg_id
    except Exception as e:
        logger.error(f"Failed to send message: {e}")
        return None

@dc_cli.on(events.NewMessage(command="/help"))
def help_command(bot, accid, event):
    msg = event.msg
    is_actually_admin = _is_dc_admin(bot, accid, msg.from_id)
    admin_email = database.get_config("admin_dc_email")
    
    help_text = (
        f"👋 Welcome to Delta Chat Uptime Bot {VERSION}!\n\n"
        f"I monitor resource availability (HTTP, TCP, Ping) and alert this chat if they go offline.\n\n"
        f"**Public Commands:**\n"
        f"/add <target> [name] — Monitor a resource. Target formats:\n"
        f"  • `https://example.com` (HTTP/HTTPS)\n"
        f"  • `example.com:22` (TCP Port)\n"
        f"  • `example.com` (ICMP Ping)\n"
        f"/remove <id> — Stop monitoring a resource\n"
        f"/list — List all monitors in this chat\n"
        f"/status — Show monthly uptime statistics & web link\n"
        f"/events — View incident history and active outages\n"
        f"/history [id] — View downtime history for monitors\n"
        f"/sync — Synchronize monitors with other bots in the chat\n"
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
            f"/resilient — Toggle resilient sending mode (all relays)\n\n"
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

def fetch_html_title(url, timeout=3.0):
    import urllib.request
    try:
        req = urllib.request.Request(
            url, 
            headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)'}
        )
        with urllib.request.urlopen(req, timeout=timeout) as response:
            html_bytes = response.read(65536)
            charset = 'utf-8'
            content_type = response.headers.get('Content-Type', '')
            charset_match = re.search(r'charset=([\w-]+)', content_type, re.IGNORECASE)
            if charset_match:
                charset = charset_match.group(1)
            try:
                html_text = html_bytes.decode(charset, errors='ignore')
            except Exception:
                html_text = html_bytes.decode('utf-8', errors='ignore')
                
            match = re.search(r'<title>(.*?)</title>', html_text, re.IGNORECASE | re.DOTALL)
            if match:
                title = match.group(1).strip()
                title = html.unescape(title)
                title = re.sub(r'\s+', ' ', title)
                if title:
                    return title
    except Exception as e:
        logger.warning(f"Could not fetch title for {url}: {e}")
    return None

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
    
    try:
        check_type, url = parse_target(target)
    except ValueError as e:
        _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text=f"❌ {e}"))
        return
        
    name = parts[1] if len(parts) > 1 else None
    if not name:
        if check_type == "http":
            fetched_title = fetch_html_title(url)
            name = fetched_title if fetched_title else target
        else:
            name = target
    

        
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
        
        ssl_info = ""
        if r.get("url", "").startswith("https://"):
            exp_ts = r.get("ssl_expiry_date")
            if exp_ts:
                now_ts = int(time.time())
                d_left = int((exp_ts - now_ts) / 86400)
                exp_date_str = datetime.datetime.fromtimestamp(exp_ts, tz=datetime.timezone.utc).strftime('%Y-%m-%d')
                if d_left < 0:
                    ssl_info = f" | SSL: 🚨 Expired (`{exp_date_str}`)"
                elif d_left <= 7:
                    ssl_info = f" | SSL: ⚠️ `{d_left}d` left (`{exp_date_str}`)"
                else:
                    ssl_info = f" | SSL: 🔒 `{d_left}d` left (`{exp_date_str}`)"
            else:
                ssl_info = " | SSL: 🔒 Pending check"

        reply += (
            f"{emoji_status} `ID: {r['id']}` **{r['name']}**\n"
            f"  Target: `{r['url']}` ({r['type'].upper()})\n"
            f"  Uptime 30d: `{uptime:.2f}%` | Status: `{r['status'].upper()}`{ssl_info}\n\n"
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

@dc_cli.on(events.NewMessage(command="/events"))
@dc_cli.on(events.NewMessage(command="/incidents"))
def events_command(bot, accid, event):
    msg = event.msg
    chat_id = msg.chat_id
    
    recent_incs = database.get_recent_incidents(chat_id, limit=10)
    
    if not recent_incs:
        _dc_send_msg_with_stats(bot, accid, chat_id, MsgData(
            text="✨ **No incidents recorded in this chat!**\nAll monitored resources have been running smoothly."
        ))
        return
        
    lines = [f"📋 **Incident Log for this Chat ({len(recent_incs)} most recent):**\n"]
    
    for inc in recent_incs:
        inc_id = inc["id"]
        status = inc["status"]
        started_at = inc["started_at"]
        resolved_at = inc["resolved_at"]
        
        start_str = datetime.datetime.fromtimestamp(started_at, tz=datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
        
        if status == "ongoing":
            duration_str = format_duration(int(time.time()) - started_at)
            lines.append(
                f"• 🚨 **Incident #{inc_id}** — `Ongoing`\n"
                f"  Started: `{start_str} UTC` (active for `{duration_str}`)"
            )
        else:
            resolved_str = datetime.datetime.fromtimestamp(resolved_at, tz=datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S') if resolved_at else "Resolved"
            duration = max(1, (resolved_at or int(time.time())) - started_at)
            duration_str = format_duration(duration)
            lines.append(
                f"• ✅ **Incident #{inc_id}** — `Resolved`\n"
                f"  Duration: `{duration_str}` (`{start_str}` → `{resolved_str} UTC`)"
            )
            
    _dc_send_msg_with_stats(bot, accid, chat_id, MsgData(text="\n".join(lines)))

@dc_cli.on(events.NewMessage(command="/history"))
def history_command(bot, accid, event):
    msg = event.msg
    chat_id = msg.chat_id
    payload = (event.payload or "").strip()
    
    if not payload:
        resources = database.get_resources(chat_id)
        if not resources:
            _dc_send_msg_with_stats(bot, accid, chat_id, MsgData(
                text="ℹ️ No resources monitored in this chat. Add one with `/add <target>`."
            ))
            return
            
        lines = [
            "📜 **Monitor Downtime History Guide**\n",
            "To view the detailed outage log for a specific monitor, use `/history <id>`.\n",
            "**Monitors in this chat:**"
        ]
        for r in resources:
            name = r["name"] or r["url"]
            uptime_val = database.get_resource_uptime_30d(r["id"])
            lines.append(f"• `ID: {r['id']}` **{name}** — 30d Uptime: `{uptime_val:.2f}%`")
            
        lines.append("\n💡 Tip: Use `/events` to view the full incident history of this chat.")
        _dc_send_msg_with_stats(bot, accid, chat_id, MsgData(text="\n".join(lines)))
        return
        
    try:
        res_id = int(payload)
    except ValueError:
        _dc_send_msg_with_stats(bot, accid, chat_id, MsgData(text="❌ Invalid monitor ID. Usage: `/history <id>`"))
        return
        
    resources = database.get_resources(chat_id)
    target_res = next((r for r in resources if r["id"] == res_id), None)
    if not target_res:
        _dc_send_msg_with_stats(bot, accid, chat_id, MsgData(text=f"❌ Monitor ID `{res_id}` not found in this chat."))
        return
        
    events_list = database.get_resource_downtime_events(res_id, limit=10)
    uptime_val = database.get_resource_uptime_30d(res_id)
    r_name = target_res["name"] or target_res["url"]
    r_type = target_res["type"].upper()
    
    lines = [
        f"📜 **Downtime History for ID {res_id} ({r_name})**",
        f"Target: `{target_res['url']}` ({r_type})",
        f"Uptime 30d: `{uptime_val:.2f}%`\n"
    ]
    
    if not events_list:
        lines.append("✨ No downtime events recorded in the last 30 days!")
    else:
        lines.append(f"**Recorded Outages ({len(events_list)} most recent):**")
        for ev in events_list:
            went_down = ev["went_down_at"]
            went_up = ev["went_up_at"]
            error_reason = ev.get("error_msg") or "Outage"
            
            down_str = datetime.datetime.fromtimestamp(went_down, tz=datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
            
            if went_up:
                up_str = datetime.datetime.fromtimestamp(went_up, tz=datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
                duration_str = format_duration(max(1, went_up - went_down))
                lines.append(f"• `{down_str}` → `{up_str} UTC` (`{duration_str}`) — `{error_reason}`")
            else:
                duration_str = format_duration(max(1, int(time.time()) - went_down))
                lines.append(f"• 🔴 `{down_str} UTC` → `Ongoing` (`{duration_str}`) — `{error_reason}`")
                
    _dc_send_msg_with_stats(bot, accid, chat_id, MsgData(text="\n".join(lines)))

@dc_cli.on(events.NewMessage(command="/sync"))
def sync_command(bot, accid, event):
    msg = event.msg
    try:
        chat_info = bot.rpc.get_basic_chat_info(accid, msg.chat_id)
        if isinstance(chat_info, dict):
            chat_type = chat_info.get('chat_type', 'Single')
        else:
            chat_type = getattr(chat_info, 'chat_type', 'Single')
        is_group = str(chat_type) in ("Group", "Mailinglist", "OutBroadcast", "InBroadcast")
    except Exception:
        is_group = False

    if not is_group:
        _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(
            text="ℹ️ Synchronization is only available in group chats containing multiple Uptime Bot instances."
        ))
        return

    # Check rate limit (1 minute per chat for non-admins)
    is_admin = _is_dc_admin(bot, accid, msg.from_id)
    if not is_admin:
        now = time.time()
        last_sync = last_sync_times.get(msg.chat_id, 0.0)
        if now - last_sync < 60.0:
            remaining = int(60.0 - (now - last_sync))
            _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(
                text=f"⚠️ Command `/sync` is rate-limited. Please wait {remaining}s before trying again."
            ))
            return
        last_sync_times[msg.chat_id] = now

    resources = database.get_resources(msg.chat_id)
    sync_list = []
    for r in resources:
        sync_list.append({
            "url": r["url"],
            "name": r["name"],
            "type": r["type"],
            "interval": r.get("interval", 60)
        })

    sync_data = json.dumps(sync_list)
    reply = (
        "🔄 **Uptime Bot Synchronization**\n"
        "Here are the resources monitored by this bot instance:\n\n"
    )
    if sync_list:
        for r in sync_list:
            reply += f"• `{r['url']}` ({r['name']}) [{r['type'].upper()}]\n"
    else:
        reply += "_No resources monitored._\n"

    reply += f"\n[UPTIME_BOT_SYNC_DATA]\n{sync_data}\n[/UPTIME_BOT_SYNC_DATA]"
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

    # Get connectivity status
    connectivity_label = "❓ Unknown"
    try:
        connectivity = bot.rpc.get_connectivity(accid)
        if connectivity >= 3000:
            connectivity_label = "🔄 Working"
        elif connectivity >= 2000:
            connectivity_label = "🟡 Connecting"
        else:
            connectivity_label = "🔴 Not connected"
    except Exception:
        pass

    # Get connectivity HTML to parse per-transport status
    connectivity_html = ""
    try:
        connectivity_html = bot.rpc.get_connectivity_html(accid)
    except Exception:
        pass

    # Get resilient sending mode status
    resilient_on = False
    try:
        resilient_on = database.get_config("resilient") == "1"
    except Exception:
        pass

    # Get per-transport statistics from database
    stats_map = {}
    for s in database.get_all_transport_stats():
        stats_map[s['addr']] = s

    active_addr = bot.rpc.get_config(accid, "configured_addr") or bot.rpc.get_config(accid, "addr")
    transport_addrs = []
    for t in transports:
        addr = t.get('addr', '') if isinstance(t, dict) else getattr(t, 'addr', '')
        transport_addrs.append(addr)

    reply = f"🔌 **Mail Relays (Transports)**\n\nStatus: {connectivity_label}\n\n"

    import re
    for addr in transport_addrs:
        # Determine status label from HTML
        status_label = "❓ Unknown"
        if connectivity_html:
            domain = addr.split('@')[-1] if '@' in addr else addr
            pattern = rf'class="([^"]+)\s+dot".*?<b>{re.escape(domain)}:</b>\s*([^<]+)'
            match = re.search(pattern, connectivity_html, re.IGNORECASE)
            if match:
                color = match.group(1).lower()
                status_text = match.group(2).strip().lower()
                if "yellow" in color or "connecting" in status_text:
                    status_label = "🟡 Connecting"
                elif "green" in color:
                    status_label = "🔄 Working"
                elif "red" in color or "lost" in status_text or "error" in status_text:
                    status_label = "🔴 Not connected"

        is_used = resilient_on or (addr == active_addr)
        used_str = " ✔︎ Used for sending:" if is_used else ":"
        reply += f"**{status_label}**{used_str} `{addr}`\n"

        stats = stats_map.get(addr)
        if stats:
            reply += f"  📤 Sent: {stats['msgs_sent']}  📥 Received: {stats['msgs_received']}\n"
            if stats.get('last_sent_at'):
                import datetime
                last_sent = datetime.datetime.fromtimestamp(stats['last_sent_at']).strftime('%Y-%m-%d %H:%M')
                reply += f"  Last sent: {last_sent}\n"
            if stats.get('last_received_at'):
                import datetime
                last_recv = datetime.datetime.fromtimestamp(stats['last_received_at']).strftime('%Y-%m-%d %H:%M')
                reply += f"  Last received: {last_recv}\n"
        else:
            reply += f"  📤 Sent: 0  📥 Received: 0\n"
        reply += "\n"

    reply += f"Total transports: {len(transport_addrs)}"
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
        _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text="❌ Only the bot administrator can use /resilient."))
        return

    arg = event.payload.strip().lower() if event.payload else ""

    try:
        current = database.get_config("resilient") == "1"
        if not arg:
            status = "enabled" if current else "disabled"
            _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text=f"ℹ️ Resilient sending mode is currently {status}."))
            return

        if arg in ("on", "1", "true"):
            database.set_config("resilient", "1")
            _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text="✅ Resilient sending mode enabled. Each outgoing message will be sent via all connected transports."))
        elif arg in ("off", "0", "false"):
            database.set_config("resilient", "0")
            _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text="❌ Resilient sending mode disabled."))
        else:
            _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text="❌ Invalid argument. Use '/resilient on', '/resilient off', or '/resilient' to get status."))
    except Exception as e:
        _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text=f"❌ Failed to update resilient mode: {e}"))

resilient_lock = threading.Lock()

def _setup_resilient_mode(bot):
    original_send_msg = bot.rpc.send_msg

    def patched_send_msg(account_id, chat_id, msg_data):
        try:
            is_resilient = database.get_config("resilient") == "1"
        except Exception:
            is_resilient = False

        if not is_resilient:
            return original_send_msg(account_id, chat_id, msg_data)

        try:
            transports = bot.rpc.list_transports(account_id)
        except Exception:
            transports = []

        if len(transports) <= 1:
            return original_send_msg(account_id, chat_id, msg_data)

        initial_addr = None
        try:
            initial_addr = bot.rpc.get_config(account_id, "configured_addr") or bot.rpc.get_config(account_id, "addr")
        except Exception:
            pass

        # 1. Send the message normally via the current primary transport (non-blocking queueing)
        try:
            msg_id = original_send_msg(account_id, chat_id, msg_data)
            bot.logger.info(f"Resilient send: initial msg queued with ID {msg_id} on transport {initial_addr}.")
        except Exception as send_err:
            bot.logger.error(f"Resilient send: failed to queue initial message: {send_err}")
            return None

        # Background worker to handle resending to other transports sequentially
        def bg_resend_worker(m_id, init_addr, t_list):
            bot.logger.info(f"Resilient send: starting background sender for msg {m_id}")
            with resilient_lock:
                bot.logger.info(f"Resilient send bg: waiting for initial delivery of msg {m_id} on {init_addr}...")
                start_time = time.time()
                delivered = False
                while time.time() - start_time < 10:
                    try:
                        msg_snapshot = bot.rpc.get_message(account_id, m_id)
                        state = msg_snapshot.get('state') if isinstance(msg_snapshot, dict) else getattr(msg_snapshot, 'state', None)
                        if state in (26, 28):
                            bot.logger.info(f"Resilient send bg: initial msg {m_id} delivered successfully on {init_addr}.")
                            delivered = True
                            break
                        if state == 24:
                            bot.logger.warning(f"Resilient send bg: initial msg {m_id} failed on {init_addr}.")
                            break
                    except Exception as poll_err:
                        bot.logger.debug(f"Resilient send bg initial poll error: {poll_err}")
                    time.sleep(0.5)

                if not delivered:
                    bot.logger.warning(f"Resilient send bg: initial msg {m_id} did not deliver on {init_addr} within timeout.")

                # 2. Resend on all other transports
                for t in t_list:
                    t_addr = t.get('addr') if isinstance(t, dict) else getattr(t, 'addr', None)
                    if not t_addr or (init_addr and t_addr.lower() == init_addr.lower()):
                        continue

                    bot.logger.info(f"Resilient send bg: switching primary transport to {t_addr}")
                    try:
                        bot.rpc.set_config(account_id, "configured_addr", t_addr)
                        time.sleep(1)
                    except Exception as switch_err:
                        bot.logger.error(f"Resilient send bg: failed to switch transport to {t_addr}: {switch_err}")
                        continue

                    try:
                        bot.logger.info(f"Resilient send bg: resending msg {m_id} on transport {t_addr}...")
                        bot.rpc.resend_messages(account_id, [m_id])

                        # Wait up to 10 seconds for the resent message to be delivered/failed
                        start_time = time.time()
                        delivered = False
                        while time.time() - start_time < 10:
                            try:
                                msg_snapshot = bot.rpc.get_message(account_id, m_id)
                                state = msg_snapshot.get('state') if isinstance(msg_snapshot, dict) else getattr(msg_snapshot, 'state', None)
                                if state in (26, 28):
                                    bot.logger.info(f"Resilient send bg: msg {m_id} delivered successfully on {t_addr}.")
                                    delivered = True
                                    break
                                if state == 24:
                                    bot.logger.warning(f"Resilient send bg: msg {m_id} failed on {t_addr}.")
                                    break
                            except Exception as poll_err:
                                bot.logger.debug(f"Resilient send bg poll error: {poll_err}")
                            time.sleep(0.5)

                        if not delivered:
                            bot.logger.warning(f"Resilient send bg: msg {m_id} did not deliver on {t_addr} within timeout.")
                    except Exception as resend_err:
                        bot.logger.error(f"Resilient send bg: failed to resend message on transport {t_addr}: {resend_err}")

                # 3. Restore the initial primary transport configuration
                if init_addr:
                    try:
                        bot.logger.info(f"Resilient send bg: restoring initial primary transport to {init_addr}")
                        bot.rpc.set_config(account_id, "configured_addr", init_addr)
                    except Exception as restore_err:
                        bot.logger.error(f"Resilient send bg: failed to restore transport to {init_addr}: {restore_err}")

        # Start the background thread for resilient sending
        threading.Thread(target=bg_resend_worker, args=(msg_id, initial_addr, transports), daemon=True).start()

        return msg_id

    bot.rpc.send_msg = patched_send_msg

_message_failover_attempts = {}

@dc_cli.on(events.RawEvent(events.EventType.MSG_FAILED))
def on_msg_failed(bot, accid, event):
    """Handle message sending failures by switching to a backup transport temporarily with backoff."""
    try:
        if database.get_config("resilient") == "1":
            return
    except Exception:
        pass

    msg_id = getattr(event, 'msg_id', None)
    if not msg_id:
        return

    try:
        global _message_failover_attempts
        if len(_message_failover_attempts) > 1000:
            _message_failover_attempts.clear()

        # Retrieve or initialize tracking state for this message
        state = _message_failover_attempts.get(msg_id)
        if state is None:
            state = {'count': 0, 'transports': set()}
            _message_failover_attempts[msg_id] = state

        # Stop retrying if we reached the maximum attempt limit (e.g. 10 attempts)
        if state['count'] >= 10:
            return

        state['count'] += 1

        # Retrieve message and verify it is indeed in failed state (state 24)
        try:
            msg_snapshot = bot.rpc.get_message(accid, msg_id)
            msg_state = msg_snapshot.get('state') if isinstance(msg_snapshot, dict) else getattr(msg_snapshot, 'state', None)
            if msg_state != 24:
                return
        except Exception:
            return

        # Fetch chat details to include in logs
        chat_id = None
        if isinstance(msg_snapshot, dict):
            chat_id = msg_snapshot.get('chat_id') or msg_snapshot.get('chatId')
        else:
            chat_id = getattr(msg_snapshot, 'chat_id', getattr(msg_snapshot, 'chatId', None))
            
        chat_name = "Unknown"
        if chat_id:
            try:
                chat_info = bot.rpc.get_full_chat_by_id(accid, chat_id)
                if isinstance(chat_info, dict):
                    chat_name = chat_info.get('name', 'Unknown')
                else:
                    chat_name = getattr(chat_info, 'name', 'Unknown')
            except Exception:
                pass

        # Check if it's a permanent E2E encryption failure
        msg_error = msg_snapshot.get('error') if isinstance(msg_snapshot, dict) else getattr(msg_snapshot, 'error', None)
        if msg_error:
            msg_error_lower = msg_error.lower()
            if "encryption" in msg_error_lower or "unencrypted" in msg_error_lower or "шифр" in msg_error_lower or "зашифр" in msg_error_lower:
                bot.logger.warning(
                    f"Permanent E2E encryption failure for message {msg_id} in chat '{chat_name}' (ID: {chat_id}): {msg_error}. "
                    f"Stopping failover attempts immediately."
                )
                return

        # List all configured transports
        try:
            transports = bot.rpc.list_transports(accid)
        except Exception:
            transports = []

        if len(transports) <= 1:
            bot.logger.info(f"Message {msg_id} failed to send, but only {len(transports)} transport(s) configured. Cannot failover.")
            return

        current_addr = bot.rpc.get_config(accid, "configured_addr") or bot.rpc.get_config(accid, "addr")
        if not current_addr:
            return

        # Find current transport index
        current_idx = -1
        for idx, t in enumerate(transports):
            t_addr = t.get('addr') if isinstance(t, dict) else getattr(t, 'addr', None)
            if t_addr and t_addr.lower() == current_addr.lower():
                current_idx = idx
                break

        if current_idx == -1:
            bot.logger.warning(f"Current transport {current_addr} not found in transports list.")
            current_idx = 0

        # Try to find the next transport
        next_idx = (current_idx + 1) % len(transports)
        next_t = transports[next_idx]
        next_addr = next_t.get('addr') if isinstance(next_t, dict) else getattr(next_t, 'addr', None)

        if not next_addr or next_addr.lower() == current_addr.lower():
            bot.logger.info("No alternative transport available for failover.")
            return

        # Check if we have already tried this transport for this message
        if next_addr.lower() in state['transports']:
            if len(state['transports']) >= len(transports):
                bot.logger.warning(f"All available transports have been tried for message {msg_id}. Stopping failover.")
                return

        state['transports'].add(current_addr.lower())

        # Calculate exponential backoff delay: 5, 10, 20, 40, 80, 160... seconds (max 5 minutes)
        delay = min(300, 5 * (2 ** (state['count'] - 1)))
        bot.logger.warning(
            f"Resilient Failover: Message {msg_id} (Chat: {chat_name}, ID: {chat_id}) failed on {current_addr} (attempt {state['count']}/10). "
            f"Scheduling resend on transport {next_addr} in {delay}s."
        )

        init_addr = current_addr

        # Schedule the resend asynchronously using a non-blocking Timer thread
        def delayed_resend():
            try:
                bot.logger.info(f"Executing scheduled resend for message {msg_id} in chat '{chat_name}' (ID: {chat_id}) on transport {next_addr}...")
                with resilient_lock:
                    # Switch configured_addr to next transport temporarily
                    bot.rpc.set_config(accid, "configured_addr", next_addr)
                    time.sleep(1) # Give core a moment to reconfigure
                    
                    bot.rpc.resend_messages(accid, [msg_id])
                    
                    # Wait up to 10 seconds for the resent message to be delivered/failed
                    start_time = time.time()
                    delivered = False
                    while time.time() - start_time < 10:
                        try:
                            raw_msg = bot.rpc.get_message(accid, msg_id)
                            if raw_msg:
                                from deltachat2 import AttrDict
                                msg_snapshot = AttrDict(raw_msg)
                                state = msg_snapshot.get('state') if isinstance(msg_snapshot, dict) else getattr(msg_snapshot, 'state', None)
                                if state in (26, 28):
                                    bot.logger.info(f"Resilient Failover bg: msg {msg_id} delivered successfully on {next_addr}.")
                                    delivered = True
                                    break
                                if state == 24:
                                    bot.logger.warning(f"Resilient Failover bg: msg {msg_id} failed on {next_addr}.")
                                    break
                        except Exception as poll_err:
                            bot.logger.debug(f"Resilient Failover bg poll error: {poll_err}")
                        time.sleep(0.5)

                    if not delivered:
                        bot.logger.warning(f"Resilient Failover bg: msg {msg_id} did not deliver on {next_addr} within timeout.")

            except Exception as resend_err:
                bot.logger.warning(f"Error executing scheduled resend for message {msg_id} in chat '{chat_name}' (ID: {chat_id}): {resend_err}")
                err_str = str(resend_err).lower()
                if "e2e encryption" in err_str or "encryption" in err_str:
                    bot.logger.warning(f"E2E encryption error detected during resend of msg {msg_id} in chat '{chat_name}'. Stopping further failovers.")
                    try:
                        _message_failover_attempts[msg_id]['count'] = 10
                    except Exception:
                        pass
            finally:
                # Always restore the initial primary transport address!
                try:
                    bot.logger.info(f"Resilient Failover bg: restoring primary transport to {init_addr}")
                    bot.rpc.set_config(accid, "configured_addr", init_addr)
                except Exception as restore_err:
                    bot.logger.error(f"Resilient Failover bg: failed to restore transport to {init_addr}: {restore_err}")

        threading.Timer(delay, delayed_resend).start()

    except Exception as e:
        bot.logger.error(f"Error handling message failover for message {msg_id}: {e}")

@dc_cli.on_init
def on_init(bot, args):
    setup_custom_command_parser(bot, ALLOWED_PREFIXES)
    bot.logger.info(f"Initializing Uptime Bot v{VERSION}...")
    
    global dc_bot_instance, dc_accid
    dc_bot_instance = bot
    _setup_resilient_mode(bot)
    
    for accid in bot.rpc.get_all_account_ids():
        dc_accid = accid
        try:
            bot_name = os.environ.get("DISPLAY_NAME", "Delta Chat Uptime Bot")
            bot.rpc.set_config(accid, "displayname", bot_name)
            
            status_text = os.environ.get("STATUS_TEXT", "Monitors resource availability (HTTP, TCP, Ping) and alerts on outages: https://github.com/mrgluek/deltachat_uptime")
            bot.rpc.set_config(accid, "selfstatus", status_text)
            
            # Set bot avatar from custom path if specified, else fallback to defaults
            avatar_env = os.environ.get("AVATAR_PATH")
            avatar_paths = []
            base_dir = os.path.dirname(os.path.abspath(__file__))
            if avatar_env:
                if os.path.isabs(avatar_env):
                    avatar_paths.append(avatar_env)
                else:
                    avatar_paths.append(os.path.join(base_dir, avatar_env))
                    avatar_paths.append(os.path.abspath(avatar_env))
            
            # Default fallback paths
            avatar_paths.extend([
                os.path.join(base_dir, "icon.png"),
                os.path.join(base_dir, "icon.jpg")
            ])
            
            for path in avatar_paths:
                if os.path.exists(path):
                    bot.rpc.set_config(accid, "selfavatar", path)
                    bot.logger.info(f"Avatar set from {path}")
                    break
            else:
                bot.logger.warning(f"No avatar found in configured or default paths.")
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
    bot.logger.info(f"Uptime Bot v{VERSION} is now fully running. Waiting for events...")
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

@dc_cli.on(events.NewMessage(is_bot=None))
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
    
    if "[UPTIME_BOT_SYNC_DATA]" in text:
        logger.info(f"[SYNC RECEIVE] Found payload. from_id={msg.from_id}, is_info={msg.is_info}")
    
    if msg.from_id == 1:
        return

    if "[UPTIME_BOT_SYNC_DATA]" in text and "[/UPTIME_BOT_SYNC_DATA]" in text:
        logger.info(f"[SYNC RECEIVE] Processing sync data payload...")
        try:
            start_idx = text.find("[UPTIME_BOT_SYNC_DATA]") + len("[UPTIME_BOT_SYNC_DATA]")
            end_idx = text.find("[/UPTIME_BOT_SYNC_DATA]")
            json_str = text[start_idx:end_idx].strip()
            sync_list = json.loads(json_str)
            logger.info(f"[SYNC RECEIVE] Parsed json: {sync_list}")
            
            if not isinstance(sync_list, list):
                logger.warning("[SYNC RECEIVE] Payload is not a list. Ignoring.")
                return
            
            # Limit the sync payload to a maximum of 50 items to avoid DB spam
            sync_list = sync_list[:50]
            
            added_count = 0
            added_resources = []
            for item in sync_list:
                if not isinstance(item, dict):
                    continue
                url = item.get("url")
                name = item.get("name")
                check_type = item.get("type")
                
                try:
                    interval = int(item.get("interval", 60))
                except (TypeError, ValueError):
                    interval = 60
                
                # Security: Force interval to be at least 60 seconds
                interval = max(60, interval)
                
                if url and check_type in ("http", "ping", "tcp"):
                    # Security: validate URL format and expected type
                    try:
                        expected_type, validated_url = parse_target(url)
                        if expected_type == check_type:
                            res_id = database.add_resource(msg.chat_id, validated_url, name or validated_url, check_type, interval)
                            if res_id is not None:
                                added_count += 1
                                added_resources.append(f"• `{validated_url}` ({name or validated_url}) [{check_type.upper()}]")
                    except ValueError:
                        # Skip invalid URL
                        continue
            
            if added_count > 0:
                reply = f"📥 **Sync Complete!**\nAdded {added_count} new resource(s) from the other bot:\n" + "\n".join(added_resources)
                _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text=reply))
            else:
                _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text="📥 **Sync Complete!**\nNo new resources to add (already up-to-date)."))
        except Exception as e:
            logger.error(f"Error parsing sync data: {e}")
        return

    # Auto-greet new users in private chat
    try:
        chat_info = bot.rpc.get_basic_chat_info(accid, msg.chat_id)
        if isinstance(chat_info, dict):
            chat_type = chat_info.get('chat_type', 'Single')
        else:
            chat_type = getattr(chat_info, 'chat_type', 'Single')
        is_private = str(chat_type) == "Single"
            
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

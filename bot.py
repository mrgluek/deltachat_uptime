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
import shlex
import secrets
from urllib.parse import urlparse
import aiohttp
from aiohttp import web
from deltachat2 import events, MsgData
from deltabot_cli import BotCli

import database

# Initialize logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("uptime_bot")
VERSION = "2.5.0"
USER_AGENT = f"DeltaChat-Uptime-Bot/{VERSION} (https://git.gluek.info/gluek/deltachat_uptime)"

dc_cli = BotCli("uptimebot")
bot_qr_cache = {}
last_sync_times = {}

# Global references
dc_bot_instance = None
dc_accid = None
async_event_loop = None

# Peering globals
pending_peer_checks = {} # req_id -> (Future, expected_count, list_of_responses)
last_peer_telemetry_broadcast = 0.0

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

async def request_peer_cross_checks(target_dict: dict, timeout: float = 8.0) -> list[dict]:
    """Broadcasts a cross-check request to all configured remote peers in 1:1 DMs and waits for responses."""
    peers = await asyncio.to_thread(database.get_all_peers)
    if not peers or not dc_bot_instance or dc_accid is None:
        return []

    req_id = secrets.token_hex(6)
    req_payload = {
        "req_id": req_id,
        "url": target_dict["url"],
        "type": target_dict.get("type", "http"),
        "expected_keyword": target_dict.get("expected_keyword"),
        "node_name": database.get_local_node_name()
    }
    msg_text = f"[UPTIME_PEER_CHECK_REQ]\n{json.dumps(req_payload)}\n[/UPTIME_PEER_CHECK_REQ]"

    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        return []

    fut = loop.create_future()
    responses = []

    valid_peers = []
    for p in peers:
        chat_id = p.get("chat_id")
        if not chat_id and p.get("email"):
            try:
                contact_id = await asyncio.to_thread(dc_bot_instance.rpc.create_contact, dc_accid, p["email"], p.get("node_name") or p["email"])
                chat_id = await asyncio.to_thread(dc_bot_instance.rpc.create_chat_by_contact_id, dc_accid, contact_id)
                await asyncio.to_thread(database.add_or_update_peer, p["email"], p.get("node_name"), chat_id)
            except Exception as e:
                logger.warning(f"Could not resolve chat_id for peer {p['email']}: {e}")
                continue
        if chat_id:
            valid_peers.append((p, chat_id))

    if not valid_peers:
        return []

    pending_peer_checks[req_id] = (fut, len(valid_peers), responses)

    for p, chat_id in valid_peers:
        try:
            await asyncio.to_thread(_dc_send_msg_with_stats, dc_bot_instance, dc_accid, chat_id, MsgData(text=msg_text))
        except Exception as e:
            logger.warning(f"Failed to send cross-check request to peer {p.get('email')}: {e}")

    try:
        await asyncio.wait_for(fut, timeout=timeout)
    except asyncio.TimeoutError:
        logger.info(f"Cross-check req_id {req_id} timed out waiting for all peer responses (got {len(responses)}/{len(valid_peers)})")
    except Exception as e:
        logger.warning(f"Error during peer cross-check wait: {e}")
    finally:
        pending_peer_checks.pop(req_id, None)

    return responses

async def broadcast_telemetry_to_peers():
    """Periodically sends local monitor telemetry to all configured peers via 1:1 chat."""
    if not dc_bot_instance or dc_accid is None:
        return
    peers = await asyncio.to_thread(database.get_all_peers)
    if not peers:
        return
        
    resources = await asyncio.to_thread(database.get_all_resources)
    if not resources:
        return
        
    seen_urls = set()
    metrics = []
    now = int(time.time())
    for r in resources:
        url = r.get("url")
        if not url or url in seen_urls:
            continue
        seen_urls.add(url)
        metrics.append({
            "url": url,
            "name": r.get("name") or url,
            "type": r.get("type") or "http",
            "expected_keyword": r.get("expected_keyword"),
            "status": r.get("status", "unknown"),
            "latency_ms": r.get("last_latency_ms"),
            "last_checked": r.get("last_checked") or now
        })
        
    if not metrics:
        return
        
    self_addr = _get_self_addr(dc_bot_instance, dc_accid)
    payload = {
        "node_name": database.get_local_node_name(),
        "sender_email": self_addr,
        "timestamp": now,
        "metrics": metrics[:100]
    }
    msg_text = f"[UPTIME_PEER_METRICS]\n{json.dumps(payload)}\n[/UPTIME_PEER_METRICS]"
    
    for p in peers:
        chat_id = p.get("chat_id")
        if not chat_id and p.get("email"):
            try:
                contact_id = await asyncio.to_thread(dc_bot_instance.rpc.create_contact, dc_accid, p["email"], p.get("node_name") or p["email"])
                chat_id = await asyncio.to_thread(dc_bot_instance.rpc.create_chat_by_contact_id, dc_accid, contact_id)
                await asyncio.to_thread(database.add_or_update_peer, p["email"], p.get("node_name"), chat_id)
            except Exception:
                continue
        if chat_id:
            try:
                await asyncio.to_thread(_dc_send_msg_with_stats, dc_bot_instance, dc_accid, chat_id, MsgData(text=msg_text))
            except Exception as e:
                logger.warning(f"Failed to push telemetry to peer {p.get('email')}: {e}")

# Async event loop and task tracking for check scheduler
async_event_loop = None
running_resource_ids = set()
running_lock = asyncio.Lock()
index_page_html_cache = None

def setup_custom_command_parser(bot):
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
            suffix_lower = suffix.lower().strip()
            
            if suffix_lower:
                # 1. Get bot's self address
                try:
                    contact = bot.rpc.get_contact(accid, 1)
                    self_address = getattr(contact, 'address', '') or (contact.get('address') if isinstance(contact, dict) else '')
                except Exception:
                    self_address = ""
                if not self_address:
                    try:
                        self_address = bot.rpc.get_config(accid, "configured_addr") or bot.rpc.get_config(accid, "addr") or ""
                    except Exception:
                        self_address = ""
                self_address = self_address.lower()

                # 2. Derive this bot's unique identifiers
                bot_identifiers = []
                if self_address:
                    bot_identifiers.append(self_address)
                    local_part = self_address.split("@")[0].lower()
                    bot_identifiers.append(local_part)
                
                try:
                    node_name = database.get_local_node_name()
                    if node_name:
                        clean_node = re.sub(r'[^a-zA-Z0-9_-]', '', node_name).lower()
                        if clean_node:
                            bot_identifiers.append(clean_node)
                            if "-" in clean_node:
                                bot_identifiers.append(clean_node.split("-")[0])
                            if "_" in clean_node:
                                bot_identifiers.append(clean_node.split("_")[0])
                except Exception:
                    pass

                # 3. Check if suffix matches this specific bot
                matched = False
                for ident in bot_identifiers:
                    if suffix_lower == ident:
                        matched = True
                        break
                    # If suffix is a prefix of this bot's local part (e.g. 'up' is a prefix of 'uptimebot')
                    if len(suffix_lower) >= 2 and ident.startswith(suffix_lower):
                        matched = True
                        break
                
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

def _is_dc_admin(bot, accid, contact_id, chat_id: int = None):
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
                    if chat_id:
                        database.set_config("admin_chat_id", str(chat_id))
                    return True
            if c_fp:
                 logger.warning(f"Admin fingerprint mismatch for contact {contact_id}")
                 return False
        
        if contact:
            sender_email = contact.address
            admin_email = database.get_config("admin_dc_email")
            if admin_email and admin_email.lower() == sender_email.lower():
                if chat_id:
                    database.set_config("admin_chat_id", str(chat_id))
                return True
            
    except Exception as e:
        logger.error(f"Error during admin verification: {e}")
    return False

async def send_admin_notification(text: str):
    """Sends high-priority system and probe health alerts to the configured administrator via DM."""
    if not dc_bot_instance or dc_accid is None:
        return
    admin_chat_id_str = await asyncio.to_thread(database.get_config, "admin_chat_id")
    chat_id = int(admin_chat_id_str) if admin_chat_id_str and admin_chat_id_str.isdigit() else None
    
    if not chat_id:
        admin_email = await asyncio.to_thread(database.get_config, "admin_dc_email")
        if not admin_email:
            return
        try:
            contact_id = await asyncio.to_thread(dc_bot_instance.rpc.create_contact, dc_accid, admin_email, "Admin")
            chat_id = await asyncio.to_thread(dc_bot_instance.rpc.create_chat_by_contact_id, dc_accid, contact_id)
            if chat_id:
                await asyncio.to_thread(database.set_config, "admin_chat_id", str(chat_id))
        except Exception as e:
            logger.warning(f"Failed to resolve admin chat for {admin_email}: {e}")
            return

    if chat_id:
        try:
            await asyncio.to_thread(_dc_send_msg_with_stats, dc_bot_instance, dc_accid, chat_id, MsgData(text=text))
        except Exception as e:
            logger.warning(f"Failed to send admin notification to chat {chat_id}: {e}")

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

async def run_single_check(resource) -> tuple[bool, str, int | None]:
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
                    elapsed_ms = int((time.time() - start_time) * 1000)
                    try:
                        phrase = http.HTTPStatus(resp.status).phrase
                    except ValueError:
                        phrase = "Unknown Status"
                    details = f"{resp.status} - {phrase}"
                    if 200 <= resp.status < 400:
                        # Read body up to 256KB
                        try:
                            body_bytes = await resp.content.read(262144)
                            charset = 'utf-8'
                            content_type = resp.headers.get('Content-Type', '')
                            charset_match = re.search(r'charset=([\w-]+)', content_type, re.IGNORECASE)
                            if charset_match:
                                charset = charset_match.group(1)
                            try:
                                body_text = body_bytes.decode(charset, errors='ignore')
                            except Exception:
                                body_text = body_bytes.decode('utf-8', errors='ignore')
                        except Exception as read_ex:
                            logger.warning(f"Failed to read body for {url}: {read_ex}")
                            body_text = ""

                        # 1. Custom Keyword assertion if configured
                        expected_kw = (resource.get("expected_keyword") or "").strip()
                        if expected_kw:
                            if expected_kw.lower() not in body_text.lower():
                                return False, f"200 OK (Missing keyword: \"{expected_kw}\")", elapsed_ms
                        else:
                            # 2. Background Auto-detection of hidden server error pages in 200 OK
                            body_lower = body_text.lower()
                            if "error establishing a database connection" in body_lower:
                                return False, "200 OK (Database connection error detected)", elapsed_ms
                            if "database connection failed" in body_lower and len(body_text) < 16384:
                                return False, "200 OK (Database connection failed detected)", elapsed_ms
                            title_match = re.search(r'<title>(.*?)</title>', body_text, re.IGNORECASE | re.DOTALL)
                            if title_match:
                                title_text = title_match.group(1).strip().lower()
                                for err_pat in ("502 bad gateway", "503 service unavailable", "504 gateway time-out", "database error", "error 521", "error 522", "error 523", "error 524"):
                                    if err_pat in title_text:
                                        return False, f"200 OK (Error in title: \"{err_pat.title()}\")", elapsed_ms

                        return True, details, elapsed_ms
                    else:
                        return False, details, elapsed_ms
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
            return True, f"{elapsed_ms} ms", elapsed_ms
        elif rtype == "ping":
            host = url.strip()
            if not re.match(r'^[a-zA-Z0-9.-]+$', host):
                return False, "Invalid hostname format", None
            proc = await asyncio.create_subprocess_exec(
                "ping", "-c", "1", "-W", "2", host,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL
            )
            await proc.wait()
            elapsed_ms = int((time.time() - start_time) * 1000)
            if proc.returncode == 0:
                return True, f"{elapsed_ms} ms", elapsed_ms
            else:
                return False, "Ping failed", elapsed_ms
    except asyncio.TimeoutError:
        elapsed_ms = int((time.time() - start_time) * 1000)
        return False, "Timeout", elapsed_ms
    except Exception as e:
        elapsed_ms = int((time.time() - start_time) * 1000)
        return False, str(e), elapsed_ms
    return False, "Unknown error", None

async def check_group_task(group, semaphore):
    rep = group[0]
    async with semaphore:
        if rep.get("is_probe_only"):
            res = await run_single_check(rep)
            if len(res) == 3:
                is_up, error_msg, latency_ms = res
            else:
                is_up, error_msg = res
                latency_ms = None
            status_str = "up" if is_up else "down"
            local_node = database.get_local_node_name()
            await asyncio.to_thread(database.update_probe_target_result, rep["url"], status_str, latency_ms, error_msg)
            await asyncio.to_thread(database.save_peer_measurement, rep["url"], local_node, status_str, latency_ms, error_msg)
            return

        res = await run_single_check(rep)
        if len(res) == 3:
            is_up, error_msg, latency_ms = res
        else:
            is_up, error_msg = res
            latency_ms = None
        
        # Retry logic: retry if check failed and at least one resource in the group was not already DOWN
        if not is_up and any(r["status"] != "down" for r in group):
            for retry in range(1, 3):
                for r in group:
                    if r["status"] != "down":
                        logger.info(f"Retry {retry}/2 for resource {r['id']} ({r['name'] or r['url']}) in chat {r['dc_chat_id']}")
                await asyncio.sleep(30)
                res = await run_single_check(rep)
                if len(res) == 3:
                    is_up, error_msg, latency_ms = res
                else:
                    is_up, error_msg = res
                    latency_ms = None
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

        # Peer Cross-Check: verify failing target with remote probes before marking DOWN
        if not is_up and any(r["status"] != "down" for r in group):
            try:
                peer_results = await request_peer_cross_checks(rep, timeout=8.0)
                if peer_results:
                    up_peers = [pr for pr in peer_results if pr.get("status") == "up"]
                    down_peers = [pr for pr in peer_results if pr.get("status") == "down"]
                    local_node = database.get_local_node_name()
                    if up_peers:
                        reach_details = ", ".join(f"{pr.get('node_name', 'Peer')}: {pr.get('latency_ms', '?')}ms" for pr in up_peers)
                        error_msg = f"{error_msg} (Reachable from {reach_details})"
                    elif down_peers:
                        nodes_confirmed = [pr.get('node_name', 'Peer') for pr in down_peers]
                        error_msg = f"{error_msg} [Confirmed by {', '.join(nodes_confirmed)}]"
            except Exception as ex:
                logger.warning(f"Error during peer cross-check: {ex}")
                    
        for r in group:
            if latency_ms is not None:
                await asyncio.to_thread(database.update_resource_latency, r["id"], latency_ms)
                r["last_latency_ms"] = latency_ms
                
            logger.info(f"Check result: {r['name'] or r['url']} (id: {r['id']}) in chat {r['dc_chat_id']} -> {'UP' if is_up else 'DOWN'} ({error_msg})")
            await handle_check_result(r, is_up, error_msg)

        # Save local node measurement for dashboard and telemetry sync
        local_node = database.get_local_node_name()
        status_str = "up" if is_up else "down"
        await asyncio.to_thread(database.save_peer_measurement, rep["url"], local_node, status_str, latency_ms, error_msg)

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

def format_incident_message(incident_id: int, started_at: int, resources: list[dict], is_resolved: bool = False, resolved_at: int = None, dc_chat_id: int = None, total_chat_monitors: int = None) -> str:
    start_dt = datetime.datetime.fromtimestamp(started_at, tz=datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
    now = int(time.time())
    
    total_monitors = total_chat_monitors if total_chat_monitors is not None else len(resources)
    down_resources = [r for r in resources if r.get("status") == "down" or r.get("resource_status") == "down" or r.get("went_up_at") is None]
    up_resources = [r for r in resources if (r.get("status") == "up" or r.get("resource_status") == "up") and r.get("went_up_at") is not None]
    
    if is_resolved:
        resolved_ts = resolved_at or now
        resolved_dt = datetime.datetime.fromtimestamp(resolved_ts, tz=datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
        duration = max(1, resolved_ts - started_at)
        duration_str = format_duration(duration)
        
        recovered_resources = [r for r in resources if r.get("name") or r.get("url")]
        
        if total_monitors > 0:
            lines = [
                f"✅ **Incident #{incident_id}** — `Resolved`",
                f"⏱ **Duration:** `{duration_str}` (`{start_dt}` → `{resolved_dt} UTC`)",
                f"📊 **All {total_monitors} monitors operational**"
            ]
            if recovered_resources:
                lines.append("\n**Recovered Monitors:**")
                for r in recovered_resources:
                    r_name = r.get("name") or r.get("url")
                    r_type = (r.get("type") or "HTTP").upper()
                    uptime_val = database.get_resource_uptime_30d(r["id"])
                    lines.append(f"• 🟢 `ID: {r['id']}` **{r_name}** ({r_type}) — Uptime 30d: `{uptime_val:.2f}%`")
        else:
            lines = [
                f"✅ **Incident #{incident_id}** — `Resolved`",
                f"⏱ **Duration:** `{duration_str}` (`{start_dt}` → `{resolved_dt} UTC`)",
                f"📊 **All monitored resources removed or operational**"
            ]
        return "\n".join(lines)
        
    else:
        duration = max(1, now - started_at)
        duration_str = format_duration(duration)
        down_count = len(down_resources)
        
        # Check if partially recovered
        partially_recovered = len(up_resources) > 0 and down_count > 0
        
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
            r_type = (r.get("type") or "HTTP").upper()
            d_time = max(1, now - (r.get("last_changed") or r.get("went_down_at") or started_at))
            d_str = format_duration(d_time)
            uptime_val = database.get_resource_uptime_30d(r["id"])
            lines.append(f"• 🔴 `ID: {r['id']}` **{r_name}**\n  Target: `{r['url']}` ({r_type})\n  Status: `DOWN` (down for `{d_str}`) | Uptime 30d: `{uptime_val:.2f}%`")
            
        for r in up_resources:
            r_name = r.get("name") or r.get("url")
            r_type = (r.get("type") or "HTTP").upper()
            rec_dt = datetime.datetime.fromtimestamp(r.get("last_changed") or r.get("went_up_at") or now, tz=datetime.timezone.utc).strftime('%H:%M:%S')
            uptime_val = database.get_resource_uptime_30d(r["id"])
            lines.append(f"• 🟢 `ID: {r['id']}` **{r_name}**\n  Target: `{r['url']}` ({r_type})\n  Status: `UP` (recovered at `{rec_dt} UTC`) | Uptime 30d: `{uptime_val:.2f}%`")

        return "\n".join(lines)

_incident_sync_locks = {}
_incident_sync_locks_thread_lock = threading.Lock()
_incident_last_edit_state = {}

def get_chat_incident_lock(dc_chat_id: int) -> asyncio.Lock:
    with _incident_sync_locks_thread_lock:
        if dc_chat_id not in _incident_sync_locks:
            _incident_sync_locks[dc_chat_id] = asyncio.Lock()
        return _incident_sync_locks[dc_chat_id]

def get_incident_update_interval(duration_seconds: int) -> int:
    """Return the minimum seconds required between live duration edits based on incident age."""
    if duration_seconds < 60:
        return 15       # First minute: update every 15 seconds
    elif duration_seconds < 300:
        return 30       # 1 to 5 minutes: update every 30 seconds
    elif duration_seconds < 3600:
        return 60       # 5 minutes to 1 hour: update every 1 minute
    elif duration_seconds < 86400:
        return 300      # 1 to 24 hours: update every 5 minutes
    else:
        return 3600     # After 24 hours: update once an hour

async def sync_chat_incident_state(dc_chat_id: int, force_update: bool = False):
    chat_lock = get_chat_incident_lock(dc_chat_id)
    async with chat_lock:
        resources = await asyncio.to_thread(database.get_resources, dc_chat_id)
        total_chat_monitors = len(resources) if resources else 0
        now = int(time.time())
        active_res_map = {r["id"]: r for r in (resources or [])}
        
        # Link any unlinked open downtime events to matching incident or create a new incident
        unlinked_events = await asyncio.to_thread(database.get_unlinked_open_downtime_events, dc_chat_id)
        for ev in unlinked_events:
            matching_inc = await asyncio.to_thread(database.get_active_incident_for_outage, dc_chat_id, ev["went_down_at"], 3600, True)
            if matching_inc:
                if matching_inc.get("status") == "resolved":
                    await asyncio.to_thread(database.reopen_incident, matching_inc["id"])
                await asyncio.to_thread(database.link_downtime_event_to_incident, ev["id"], matching_inc["id"])
                force_update = True
            else:
                new_inc_id = await asyncio.to_thread(database.create_incident, dc_chat_id, ev["went_down_at"])
                await asyncio.to_thread(database.link_downtime_event_to_incident, ev["id"], new_inc_id)
                force_update = True

        active_incidents = await asyncio.to_thread(database.get_active_incidents_for_chat, dc_chat_id)
        if not active_incidents:
            return

        for inc in active_incidents:
            inc_id = inc["id"]
            events = await asyncio.to_thread(database.get_incident_downtime_events, inc_id)
            
            # If any open downtime event belongs to a deleted resource, close it
            for ev in events:
                if ev["resource_id"] not in active_res_map and ev.get("went_up_at") is None:
                    await asyncio.to_thread(database.close_resource_downtime_events, ev["resource_id"], now)
                    ev["went_up_at"] = now

            open_events = [ev for ev in events if ev.get("went_up_at") is None and ev["resource_id"] in active_res_map]
            
            if open_events:
                # Incident is ongoing
                started_at = inc["started_at"]
                duration = max(0, now - started_at)
                
                status_sig = tuple(sorted((ev["resource_id"], ev.get("resource_status") or "", ev.get("went_up_at") or 0) for ev in events))
                last_edit_time, last_sig = _incident_last_edit_state.get(inc_id, (0.0, None))
                throttle_interval = get_incident_update_interval(duration)
                
                should_edit = (status_sig != last_sig) or ((now - last_edit_time) >= throttle_interval) or (inc.get("msg_id") is None)
                if not should_edit:
                    continue

                inc_resources = []
                seen_res = set()
                for ev in events:
                    rid = ev["resource_id"]
                    if rid in active_res_map and rid not in seen_res:
                        seen_res.add(rid)
                        r = active_res_map[rid]
                        is_currently_down = any(e["resource_id"] == rid and e.get("went_up_at") is None for e in events)
                        inc_resources.append({
                            "id": r["id"],
                            "name": r.get("name"),
                            "url": r.get("url"),
                            "type": r.get("type"),
                            "status": "down" if is_currently_down else "up",
                            "last_changed": r.get("last_changed") or ev.get("went_up_at") or ev.get("went_down_at"),
                            "went_down_at": ev.get("went_down_at"),
                            "went_up_at": ev.get("went_up_at")
                        })
                
                msg_text = format_incident_message(
                    inc_id,
                    started_at,
                    inc_resources,
                    is_resolved=False,
                    total_chat_monitors=total_chat_monitors
                )
                
                if dc_bot_instance and dc_accid is not None:
                    msg_id = inc.get("msg_id")
                    if msg_id:
                        try:
                            await asyncio.to_thread(
                                dc_bot_instance.rpc.send_edit_request,
                                dc_accid,
                                msg_id,
                                msg_text
                            )
                            _incident_last_edit_state[inc_id] = (now, status_sig)
                            logger.info(f"Edited Incident #{inc_id} message {msg_id} in chat {dc_chat_id}")
                        except Exception as e:
                            logger.warning(f"Failed to edit Incident message {msg_id} (sending new message): {e}")
                            try:
                                new_msg_id = await asyncio.to_thread(
                                    dc_bot_instance.rpc.send_msg,
                                    dc_accid,
                                    dc_chat_id,
                                    MsgData(text=msg_text)
                                )
                                if isinstance(new_msg_id, int):
                                    await asyncio.to_thread(database.update_incident_msg_id, inc_id, new_msg_id)
                                    _incident_last_edit_state[inc_id] = (now, status_sig)
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
                            if isinstance(new_msg_id, int):
                                await asyncio.to_thread(database.update_incident_msg_id, inc_id, new_msg_id)
                                _incident_last_edit_state[inc_id] = (now, status_sig)
                        except Exception as e:
                            logger.error(f"Failed to send incident message to chat {dc_chat_id}: {e}")

            else:
                # All events for this incident are closed -> Incident is resolved!
                _incident_last_edit_state.pop(inc_id, None)
                
                rec_resources = []
                seen_res = set()
                for ev in events:
                    rid = ev["resource_id"]
                    if rid in active_res_map and rid not in seen_res:
                        seen_res.add(rid)
                        rec_resources.append(active_res_map[rid])
                
                if rec_resources:
                    rec_names = [r.get("name") or r.get("url") for r in rec_resources]
                    summary_str = f"Recovered: {', '.join(rec_names)}"
                else:
                    summary_str = f"All {total_chat_monitors} monitors operational" if total_chat_monitors > 0 else "All monitored resources removed or operational"
                
                await asyncio.to_thread(database.resolve_incident, inc_id, now, summary_str)
                
                msg_text = format_incident_message(
                    inc_id,
                    inc["started_at"],
                    rec_resources,
                    is_resolved=True,
                    resolved_at=now,
                    total_chat_monitors=total_chat_monitors,
                    dc_chat_id=dc_chat_id
                )
                
                if dc_bot_instance and dc_accid is not None:
                    msg_id = inc.get("msg_id")
                    if msg_id:
                        try:
                            await asyncio.to_thread(
                                dc_bot_instance.rpc.send_edit_request,
                                dc_accid,
                                msg_id,
                                msg_text
                            )
                            logger.info(f"Resolved Incident #{inc_id} by editing message {msg_id} in chat {dc_chat_id}")
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

def trigger_chat_incident_sync(dc_chat_id: int, force_update: bool = False):
    """Trigger incident state sync from a synchronous handler / thread."""
    global async_event_loop
    if async_event_loop and async_event_loop.is_running():
        asyncio.run_coroutine_threadsafe(sync_chat_incident_state(dc_chat_id, force_update=force_update), async_event_loop)
    else:
        try:
            asyncio.run(sync_chat_incident_state(dc_chat_id, force_update=force_update))
        except Exception as ex:
            logger.debug(f"Direct sync_chat_incident_state invocation: {ex}")

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
    now = int(time.time())
    m_until = resource.get("maintenance_until") or 0
    in_maintenance = (now < m_until)

    if in_maintenance:
        # Resource is in maintenance window. Suppress failure transitions and incident creation.
        await asyncio.to_thread(database.update_resource_status, resource["id"], resource["status"], 0, error_msg)
        return

    status = "up" if is_up else "down"
    old_status = resource["status"]
    
    failures = 0 if is_up else (resource["consecutive_failures"] + 1)
    await asyncio.to_thread(database.update_resource_status, resource["id"], status, failures, error_msg)
    
    should_sync = False
    if old_status != status:
        if old_status != "unknown" or status == "down":
            should_sync = True
            
    if should_sync:
        await sync_chat_incident_state(resource["dc_chat_id"], force_update=True)

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
            probe_targets = await asyncio.to_thread(database.get_active_probe_targets)
            now = int(time.time())
            
            # Group due resources by (type, url)
            due_groups = collections.defaultdict(list)
            seen_urls = set()
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
                        seen_urls.add(r["url"])
                    else:
                        seen_urls.add(r["url"])

                # Add probe-only targets mirrored from peers if not already checked by local chats
                for pt in probe_targets:
                    pt_url = pt.get("url")
                    if not pt_url or pt_url in seen_urls:
                        continue
                    pt_key = f"probe_{pt_url}"
                    if pt_key in running_resource_ids:
                        continue
                    last_checked = pt.get("last_checked") or 0
                    if now - last_checked >= 60:
                        running_resource_ids.add(pt_key)
                        probe_rep = {
                            "id": pt_key,
                            "dc_chat_id": 0,
                            "url": pt_url,
                            "name": pt.get("name") or pt_url,
                            "type": pt.get("type") or "http",
                            "expected_keyword": pt.get("expected_keyword"),
                            "status": pt.get("last_status") or "unknown",
                            "is_probe_only": True
                        }
                        due_groups[(probe_rep["type"], pt_url)].append(probe_rep)
            
            tasks = []
            for target_key, group in due_groups.items():
                tasks.append(run_and_track_group(group, semaphore))
                
            if tasks:
                logger.info(f"Triggering {len(tasks)} target checks (encompassing {sum(len(g) for g in due_groups.values())} resources)...")
                asyncio.create_task(run_checks_parallel(tasks))
                
            # Periodically broadcast telemetry to configured peers (every 2 minutes)
            global last_peer_telemetry_broadcast
            if now - last_peer_telemetry_broadcast >= 120:
                last_peer_telemetry_broadcast = now
                asyncio.create_task(broadcast_telemetry_to_peers())

            # Audit any ongoing incidents across all chats to ensure self-healing
            active_incidents = await asyncio.to_thread(database.get_all_active_incidents)
            for inc in active_incidents:
                asyncio.create_task(sync_chat_incident_state(inc["dc_chat_id"]))

            # Audit peer probe liveness (alert admin if remote probe stopped responding for > 6 mins)
            newly_offline_peers = await asyncio.to_thread(database.audit_peers_offline, 360)
            for p in newly_offline_peers:
                p_node = p.get("node_name") or "Remote"
                p_email = p.get("email")
                diff_secs = max(1, now - (p.get("last_seen") or now))
                diff_str = format_duration(diff_secs)
                alert_txt = (
                    f"🚨 **Monitoring Probe Offline Alert**\n"
                    f"Probe Node: 🛰️ **{p_node}** (`{p_email}`)\n"
                    f"Last seen: `{diff_str} ago`\n\n"
                    f"⚠️ This probe is no longer responding or sending telemetry. Distributed cross-checks and multi-region metrics for this node are paused."
                )
                asyncio.create_task(send_admin_notification(alert_txt))

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
        now_ts = int(time.time())
        for r in resources:
            r_uptime = database.get_resource_uptime_30d(r["id"])
            m_until = r.get("maintenance_until") or 0
            is_maintenance = (now_ts < m_until)

            if is_maintenance:
                indicator_class = "unknown"
                status_lbl = "PAUSED"
                status_color = "var(--color-warn)"
            elif r["status"] == "up":
                indicator_class = "up"
                status_lbl = "UP"
                status_color = "var(--color-up)"
            elif r["status"] == "down":
                indicator_class = "down"
                status_lbl = "DOWN"
                status_color = "var(--color-down)"
            else:
                indicator_class = "unknown"
                status_lbl = "UNKNOWN"
                status_color = "var(--text-muted)"
            
            last_checked_str = "Never"
            if r["last_checked"]:
                last_checked_str = datetime.datetime.fromtimestamp(r["last_checked"]).strftime('%Y-%m-%d %H:%M:%S')
                
            badges_html = f'<span class="monitor-type">{r["type"]}</span>'
            if r.get("expected_keyword"):
                badges_html += f' <span class="monitor-type" style="background: rgba(56, 189, 248, 0.1); color: #38bdf8; border-color: rgba(56, 189, 248, 0.25);" title="Expected content keyword">🔍 {html.escape(r["expected_keyword"])}</span>'
            if is_maintenance:
                m_left_secs = m_until - now_ts
                m_left_str = format_duration(m_left_secs)
                badges_html += f' <span class="monitor-type" style="background: rgba(245, 158, 11, 0.15); color: #f59e0b; border-color: rgba(245, 158, 11, 0.3);">⏸️ Maintenance ({m_left_str} left)</span>'

            probe_badges_html = ""
            peer_measurements = database.get_peer_measurements_for_url(r["url"])
            local_node = database.get_local_node_name()
            remote_measurements = [pm for pm in peer_measurements if pm.get("node_name") != local_node]
            if remote_measurements:
                local_lat = f"{r['last_latency_ms']}ms" if r.get("last_latency_ms") is not None else ("UP" if r["status"] == "up" else "DOWN")
                local_badge_color = "var(--color-up)" if r["status"] == "up" else ("var(--color-down)" if r["status"] == "down" else "var(--text-muted)")
                probe_badges_html = f'<div style="display: flex; gap: 0.35rem; flex-wrap: wrap; margin-top: 0.35rem; font-size: 0.75rem;">'
                probe_badges_html += f'<span style="background: rgba(255, 255, 255, 0.05); padding: 2px 6px; border-radius: 4px; border: 1px solid rgba(255, 255, 255, 0.1);">📍 <b>{html.escape(local_node)}</b>: <span style="color: {local_badge_color};">{local_lat}</span></span>'
                for pm in remote_measurements:
                    pm_status = pm.get("status")
                    pm_lat = f"{pm['latency_ms']}ms" if pm.get("latency_ms") is not None else (pm_status.upper() if pm_status else "UNKNOWN")
                    pm_color = "var(--color-up)" if pm_status == "up" else ("var(--color-down)" if pm_status == "down" else "var(--text-muted)")
                    probe_badges_html += f'<span style="background: rgba(255, 255, 255, 0.05); padding: 2px 6px; border-radius: 4px; border: 1px solid rgba(255, 255, 255, 0.1);">🛰️ <b>{html.escape(pm["node_name"])}</b>: <span style="color: {pm_color};">{pm_lat}</span></span>'
                probe_badges_html += '</div>'

            latency_stat_html = ""
            if r.get("last_latency_ms") is not None:
                lat_ms = r["last_latency_ms"]
                if lat_ms >= 5000:
                    lat_color = "var(--color-warn)"
                elif lat_ms >= 1000:
                    lat_color = "#38bdf8"
                else:
                    lat_color = "var(--color-up)"
                latency_stat_html = f"""
                <div class="m-stat">
                    <span class="m-val" style="color: {lat_color}; font-size: 0.875rem;">{lat_ms} ms</span>
                    <span class="m-lbl">Latency</span>
                </div>
                """

            ssl_stat_html = ""
            if r.get("url", "").startswith("https://"):
                exp_ts = r.get("ssl_expiry_date")
                if exp_ts:
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
                        <div style="display: flex; gap: 0.35rem; flex-wrap: wrap; margin-top: 0.25rem;">{badges_html}</div>
                        {probe_badges_html}
                    </div>
                </div>
                <div class="monitor-stats">
                    <div class="m-stat">
                        <span class="m-val" style="color: {status_color};">{status_lbl}</span>
                        <span class="m-lbl">Status</span>
                    </div>
                    {latency_stat_html}
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
            
            # Fetch affected services for this incident
            events = database.get_incident_downtime_events(inc_id)
            affected_services_html = ""
            if events:
                service_items = []
                seen_event_urls = set()
                for ev in events:
                    s_name = ev.get("name") or ev.get("url") or f"Resource #{ev.get('resource_id')}"
                    s_url = ev.get("url")
                    if s_url in seen_event_urls:
                        continue
                    if s_url:
                        seen_event_urls.add(s_url)
                    s_err = ev.get("error_msg")
                    err_badge = f' <span style="color: var(--text-muted); font-size: 0.75rem;">({html.escape(s_err)})</span>' if s_err else ""
                    service_items.append(f'<li><b>{html.escape(s_name)}</b>{err_badge}</li>')
                
                if service_items:
                    affected_services_html = (
                        '<div style="margin-top: 0.5rem; padding-top: 0.5rem; border-top: 1px solid rgba(255, 255, 255, 0.08);">'
                        '<span style="font-size: 0.75rem; font-weight: 600; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.05em;">Affected Monitors:</span>'
                        '<ul style="margin: 0.25rem 0 0 1.25rem; font-size: 0.8125rem; color: var(--text-primary); line-height: 1.4;">'
                        + "".join(service_items) +
                        '</ul>'
                        '</div>'
                    )

            if inc_status == "ongoing":
                d_str = format_duration(int(time.time()) - started_at)
                inc_items += f"""
                <div class="monitor-card" style="border-left: 4px solid var(--color-down);">
                    <div class="monitor-info" style="display: flex; align-items: flex-start;">
                        <span class="indicator down" style="margin-top: 4px;"></span>
                        <div class="monitor-meta" style="flex: 1;">
                            <span class="monitor-name" style="color: var(--color-down);">Incident #{inc_id} — Ongoing</span>
                            <span class="monitor-url">Started: {start_str} UTC (active for {d_str})</span>
                            {affected_services_html}
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
                    <div class="monitor-info" style="display: flex; align-items: flex-start;">
                        <span class="indicator up" style="margin-top: 4px;"></span>
                        <div class="monitor-meta" style="flex: 1;">
                            <span class="monitor-name">Incident #{inc_id} — Resolved</span>
                            <span class="monitor-url">{start_str} → {resolved_str} UTC ({d_str})</span>
                            {affected_services_html}
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
                        <td><code>/remove &lt;id|url&gt;</code></td>
                        <td>Stop monitoring a resource (or reply <code>/remove</code> to alert).</td>
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
        f"/add <target> [name] [\"keyword\"] — Monitor a resource. Target formats:\n"
        f"  • `https://example.com` (HTTP/HTTPS)\n"
        f"  • `https://api.site.com Health \"status:ok\"` (Keyword assertion)\n"
        f"  • `example.com:22` (TCP Port)\n"
        f"  • `example.com` (ICMP Ping)\n"
        f"/remove <id|url> (or reply /remove) — Stop monitoring a resource\n"
        f"/pause <id|url> [dur] (or reply /pause) — Pause/mute alerts (e.g. `30m`, `2h`)\n"
        f"/resume <id|url> (or reply /resume) — Resume monitoring after maintenance\n"
        f"/keyword <id|url> [keyword|none] — Set or remove required keyword assertion\n"
        f"/list — List all monitors in this chat with uptime, latency & SSL\n"
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
            f"/nodename [name] — Set/view local probe node name (e.g. `Frankfurt-DE`)\n"
            f"/invitepeer — Generate SecureJoin E2EE invite link for pairing with other bots\n"
            f"/peers (or /probes) — List distributed peer bots and their status\n"
            f"/addpeer <email|link> [node_name] — Add remote peer bot (via email or SecureJoin invite)\n"
            f"/rmpeer <email> — Remove remote peer bot\n"
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

def parse_duration_string(s: str) -> int | None:
    if not s:
        return None
    s = s.strip().lower()
    match = re.match(r'^(\d+)\s*(m|min|mins|minute|minutes|h|hr|hrs|hour|hours|d|day|days)?$', s)
    if not match:
        return None
    val = int(match.group(1))
    unit = match.group(2) or "m"
    if unit.startswith("m"):
        return val * 60
    elif unit.startswith("h"):
        return val * 3600
    elif unit.startswith("d"):
        return val * 86400
    return val * 60

@dc_cli.on(events.NewMessage(command="/add"))
def add_command(bot, accid, event):
    msg = event.msg
    payload = event.payload.strip()
    
    if not payload:
        _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(
            text="Usage: /add <target> [name] [\"keyword\"]\n\nExamples:\n"
                 "• `/add https://google.com Google` (HTTP)\n"
                 "• `/add https://api.site.com Health \"status:ok\"` (Keyword assertion)\n"
                 "• `/add google.com:443 Google TCP` (TCP)\n"
                 "• `/add google.com Google Ping` (Ping)"
        ))
        return
        
    try:
        tokens = shlex.split(payload)
    except Exception:
        tokens = payload.split()
        
    if not tokens:
        return
        
    target = tokens[0]
    
    try:
        check_type, url = parse_target(target)
    except ValueError as e:
        _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text=f"❌ {e}"))
        return
        
    name = tokens[1] if len(tokens) > 1 else None
    expected_keyword = tokens[2] if len(tokens) > 2 else None
    
    if not name:
        if check_type == "http":
            fetched_title = fetch_html_title(url)
            name = fetched_title if fetched_title else target
        else:
            name = target
        
    res_id = database.add_resource(msg.chat_id, url, name, check_type, expected_keyword=expected_keyword)
    if res_id is None:
        _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text="❌ This target is already being monitored in this chat."))
        return
        
    kw_line = f"\n🔍 Expected Keyword: `{expected_keyword}`" if expected_keyword else ""
    _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(
        text=f"✅ Added monitor (ID: `{res_id}`):\n"
             f"🖥️ Name: **{name}**\n"
             f"🔗 Target: `{url}`\n"
             f"⚙️ Type: `{check_type.upper()}`{kw_line}\n"
             f"🕒 Checking once a minute."
    ))

@dc_cli.on(events.NewMessage(command="/rm"))
@dc_cli.on(events.NewMessage(command="/del"))
@dc_cli.on(events.NewMessage(command="/remove"))
@dc_cli.on(events.NewMessage(command="/delete"))
def remove_command(bot, accid, event):
    msg = event.msg
    payload = (event.payload or "").strip()

    # Case 1: Direct numeric ID (e.g. /delete 1)
    if payload.isdigit():
        res_id = int(payload)
        res = database.get_resource_by_id(res_id)
        if res and res["dc_chat_id"] == msg.chat_id:
            res_name = res["name"]
            res_url = res["url"]
            database.delete_resource(msg.chat_id, res_id)
            _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text=f"✅ Removed monitor: **{res_name}** (`{res_url}`) (ID: `{res_id}`)."))
            trigger_chat_incident_sync(msg.chat_id, force_update=True)
        else:
            _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text=f"❌ Monitor ID `{res_id}` not found in this chat."))
        return

    # Case 2: Target URL / name passed directly (e.g. /delete https://example.com)
    if payload:
        matched_resources = database.get_resources_by_target(msg.chat_id, payload)
        if not matched_resources:
            matched_resources = database.get_resources_matching_text(msg.chat_id, payload)

        if matched_resources:
            deleted_names = []
            for r in matched_resources:
                if database.delete_resource(msg.chat_id, r["id"]):
                    deleted_names.append(f"• **{r['name']}** (`{r['url']}`) (ID: `{r['id']}`)")

            if deleted_names:
                text = "✅ Removed monitor:\n" + "\n".join(deleted_names) if len(deleted_names) > 1 else f"✅ Removed monitor: **{matched_resources[0]['name']}** (`{matched_resources[0]['url']}`) (ID: `{matched_resources[0]['id']}`)."
                _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text=text))
                trigger_chat_incident_sync(msg.chat_id, force_update=True)
                return
        else:
            _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text=f"❌ No monitored resource matching `{payload}` found in this chat."))
            return

    # Case 3: No payload -> check if replying / quoting an incident or alert message
    quote = getattr(msg, "quote", None) or (msg.get("quote") if isinstance(msg, dict) else None)
    if quote:
        quote_msg_id = None
        if isinstance(quote, dict):
            quote_msg_id = quote.get("message_id") or quote.get("messageId")
            quote_text = quote.get("text", "")
        else:
            quote_msg_id = getattr(quote, "message_id", None) or getattr(quote, "messageId", None)
            quote_text = getattr(quote, "text", "")

        full_quote_text = quote_text or ""
        if quote_msg_id and bot and hasattr(bot, "rpc"):
            try:
                quoted_msg = bot.rpc.get_message(accid, quote_msg_id)
                if quoted_msg and hasattr(quoted_msg, "text") and quoted_msg.text:
                    full_quote_text = f"{full_quote_text}\n{quoted_msg.text}"
            except Exception as e:
                logger.debug(f"Could not fetch quoted message {quote_msg_id}: {e}")

        targets_to_delete = []

        # 3a. Check if quote_msg_id corresponds to an incident from this bot in this chat
        if quote_msg_id:
            inc = database.get_incident_by_msg_id(msg.chat_id, quote_msg_id)
            if inc:
                events = database.get_incident_downtime_events(inc["id"])
                for ev in events:
                    r = database.get_resource_by_id(ev["resource_id"])
                    if r and r["dc_chat_id"] == msg.chat_id and r not in targets_to_delete:
                        targets_to_delete.append(r)

        # 3b. Match resources by URLs/names in quote text
        if full_quote_text:
            text_matched = database.get_resources_matching_text(msg.chat_id, full_quote_text)
            for r in text_matched:
                if r not in targets_to_delete:
                    targets_to_delete.append(r)

        if targets_to_delete:
            deleted_names = []
            for r in targets_to_delete:
                if database.delete_resource(msg.chat_id, r["id"]):
                    deleted_names.append(f"• **{r['name']}** (`{r['url']}`) (ID: `{r['id']}`)")

            if deleted_names:
                text = "✅ Removed monitor:\n" + "\n".join(deleted_names) if len(deleted_names) > 1 else f"✅ Removed monitor: **{targets_to_delete[0]['name']}** (`{targets_to_delete[0]['url']}`) (ID: `{targets_to_delete[0]['id']}`)."
                _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text=text))
                trigger_chat_incident_sync(msg.chat_id, force_update=True)
            return
        else:
            logger.info(f"Ignoring /delete reply in chat {msg.chat_id}: no matching monitors found for quote {quote_msg_id}")
            return

    # Case 4: No payload and no quote
    _dc_send_msg_with_stats(
        bot, accid, msg.chat_id,
        MsgData(text="ℹ️ **Usage:**\n• `/delete <id>` — Delete monitor by ID\n• `/delete <url>` — Delete monitor by URL/domain\n• Reply `/delete` directly to an incident or outage alert message.")
    )

@dc_cli.on(events.NewMessage(command="/pause"))
@dc_cli.on(events.NewMessage(command="/mute"))
@dc_cli.on(events.NewMessage(command="/maintenance"))
def pause_command(bot, accid, event):
    msg = event.msg
    payload = (event.payload or "").strip()
    now = int(time.time())
    
    try:
        tokens = shlex.split(payload) if payload else []
    except Exception:
        tokens = payload.split() if payload else []

    target_res = []
    duration_secs = 3600 # default 1 hour
    
    if len(tokens) >= 1:
        # Check if first token is duration only (e.g. /pause 30m)
        dur = parse_duration_string(tokens[0])
        if dur is not None and len(tokens) == 1:
            duration_secs = dur
        else:
            target_ident = tokens[0]
            if len(tokens) >= 2:
                parsed_dur = parse_duration_string(tokens[1])
                if parsed_dur is not None:
                    duration_secs = parsed_dur
            
            if target_ident.isdigit():
                r = database.get_resource_by_id(int(target_ident))
                if r and r["dc_chat_id"] == msg.chat_id:
                    target_res = [r]
            else:
                target_res = database.get_resources_by_target(msg.chat_id, target_ident)
                if not target_res:
                    target_res = database.get_resources_matching_text(msg.chat_id, target_ident)
                
    # If no target specified via args, try quote/reply
    if not target_res:
        quote = getattr(msg, "quote", None) or (msg.get("quote") if isinstance(msg, dict) else None)
        if quote:
            quote_msg_id = None
            if isinstance(quote, dict):
                quote_msg_id = quote.get("message_id") or quote.get("messageId")
                quote_text = quote.get("text", "")
            else:
                quote_msg_id = getattr(quote, "message_id", None) or getattr(quote, "messageId", None)
                quote_text = getattr(quote, "text", "")

            full_quote_text = quote_text or ""
            if quote_msg_id and bot and hasattr(bot, "rpc"):
                try:
                    qmsg = bot.rpc.get_message(accid, quote_msg_id)
                    if qmsg and hasattr(qmsg, "text") and qmsg.text:
                        full_quote_text = f"{full_quote_text}\n{qmsg.text}"
                except Exception:
                    pass
                    
            if quote_msg_id:
                inc = database.get_incident_by_msg_id(msg.chat_id, quote_msg_id)
                if inc:
                    inc_events = database.get_incident_downtime_events(inc["id"])
                    for ev in inc_events:
                        r = database.get_resource_by_id(ev["resource_id"])
                        if r and r["dc_chat_id"] == msg.chat_id and r not in target_res:
                            target_res.append(r)
                            
            if not target_res and full_quote_text:
                text_matched = database.get_resources_matching_text(msg.chat_id, full_quote_text)
                for r in text_matched:
                    if r not in target_res:
                        target_res.append(r)
                    
            if not target_res:
                logger.info(f"Pause quote in chat {msg.chat_id} did not match any local resources, ignoring.")
                return

    if not target_res:
        _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(
            text="Usage: `/pause <id|url> [duration]` or reply `/pause [duration]` to an alert.\n\n"
                 "Examples:\n"
                 "• `/pause 1 30m`\n"
                 "• `/pause https://example.com 2h`\n"
                 "• Reply `/pause 1h` directly to an incident alert"
        ))
        return

    until_ts = now + duration_secs
    until_dt_str = datetime.datetime.fromtimestamp(until_ts, tz=datetime.timezone.utc).strftime('%H:%M:%S')
    dur_str = format_duration(duration_secs)
    
    paused_names = []
    for r in target_res:
        database.set_resource_maintenance(msg.chat_id, r["id"], until_ts)
        paused_names.append(f"• `ID: {r['id']}` **{r['name']}** (`{r['url']}`)")
        
    _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(
        text=f"⏸️ **Maintenance Mode Enabled** (active for `{dur_str}`, until `{until_dt_str} UTC`):\n\n" +
             "\n".join(paused_names) +
             "\n\n_Outage alerts will be suppressed until maintenance expires, or use `/resume`._"
    ))

@dc_cli.on(events.NewMessage(command="/resume"))
@dc_cli.on(events.NewMessage(command="/unpause"))
def resume_command(bot, accid, event):
    msg = event.msg
    payload = (event.payload or "").strip()
    
    target_res = []
    if payload.isdigit():
        r = database.get_resource_by_id(int(payload))
        if r and r["dc_chat_id"] == msg.chat_id:
            target_res = [r]
    elif payload:
        target_res = database.get_resources_by_target(msg.chat_id, payload)
        if not target_res:
            target_res = database.get_resources_matching_text(msg.chat_id, payload)
        
    if not target_res:
        quote = getattr(msg, "quote", None) or (msg.get("quote") if isinstance(msg, dict) else None)
        if quote:
            quote_msg_id = None
            if isinstance(quote, dict):
                quote_msg_id = quote.get("message_id") or quote.get("messageId")
                quote_text = quote.get("text", "")
            else:
                quote_msg_id = getattr(quote, "message_id", None) or getattr(quote, "messageId", None)
                quote_text = getattr(quote, "text", "")

            full_quote_text = quote_text or ""
            if quote_msg_id and bot and hasattr(bot, "rpc"):
                try:
                    qmsg = bot.rpc.get_message(accid, quote_msg_id)
                    if qmsg and hasattr(qmsg, "text") and qmsg.text:
                        full_quote_text = f"{full_quote_text}\n{qmsg.text}"
                except Exception:
                    pass
                    
            if quote_msg_id:
                inc = database.get_incident_by_msg_id(msg.chat_id, quote_msg_id)
                if inc:
                    inc_events = database.get_incident_downtime_events(inc["id"])
                    for ev in inc_events:
                        r = database.get_resource_by_id(ev["resource_id"])
                        if r and r["dc_chat_id"] == msg.chat_id and r not in target_res:
                            target_res.append(r)
                            
            if not target_res and full_quote_text:
                text_matched = database.get_resources_matching_text(msg.chat_id, full_quote_text)
                for r in text_matched:
                    if r not in target_res:
                        target_res.append(r)
                    
            if not target_res:
                logger.info(f"Resume quote in chat {msg.chat_id} did not match any local resources, ignoring.")
                return

    if not target_res:
        _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(
            text="Usage: `/resume <id|url>` or reply `/resume` to an alert."
        ))
        return

    resumed_names = []
    for r in target_res:
        database.set_resource_maintenance(msg.chat_id, r["id"], 0)
        resumed_names.append(f"• `ID: {r['id']}` **{r['name']}** (`{r['url']}`)")
        
    _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(
        text="▶️ **Resumed Monitoring:**\n\n" +
             "\n".join(resumed_names)
    ))

@dc_cli.on(events.NewMessage(command="/keyword"))
@dc_cli.on(events.NewMessage(command="/assert"))
@dc_cli.on(events.NewMessage(command="/kw"))
def keyword_command(bot, accid, event):
    msg = event.msg
    payload = (event.payload or "").strip()
    
    try:
        tokens = shlex.split(payload) if payload else []
    except Exception:
        tokens = payload.split() if payload else []
        
    if not tokens:
        _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(
            text="Usage: `/keyword <id|url> <keyword|none>`\n\n"
                 "Examples:\n"
                 "• `/keyword 1 \"Welcome to site\"`\n"
                 "• `/keyword https://api.site.com/health \"status:ok\"`\n"
                 "• `/keyword 1 none` (to remove keyword assertion)"
        ))
        return
        
    target_ident = tokens[0]
    keyword = tokens[1] if len(tokens) > 1 else None
    
    target_res = []
    if target_ident.isdigit():
        r = database.get_resource_by_id(int(target_ident))
        if r and r["dc_chat_id"] == msg.chat_id:
            target_res = [r]
    else:
        target_res = database.get_resources_by_target(msg.chat_id, target_ident)
        if not target_res:
            target_res = database.get_resources_matching_text(msg.chat_id, target_ident)
        
    if not target_res:
        _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(
            text=f"❌ No monitor found for `{target_ident}` in this chat."
        ))
        return
        
    target = target_res[0]
    if keyword is None:
        current_kw = target.get("expected_keyword")
        if current_kw:
            _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(
                text=f"🔍 Monitor `ID: {target['id']}` (**{target['name']}**) requires keyword:\n`\"{current_kw}\"`"
            ))
        else:
            _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(
                text=f"ℹ️ Monitor `ID: {target['id']}` (**{target['name']}**) does not have a required keyword configured."
            ))
        return
        
    if keyword.lower() in ("none", "clear", "remove", "off", "disable", "delete"):
        database.set_resource_keyword(msg.chat_id, target["id"], None)
        _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(
            text=f"✅ Cleared expected keyword requirement for **{target['name']}**."
        ))
    else:
        database.set_resource_keyword(msg.chat_id, target["id"], keyword)
        _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(
            text=f"✅ Set expected keyword for **{target['name']}** (`ID: {target['id']}`):\n`\"{keyword}\"`"
        ))

@dc_cli.on(events.NewMessage(command="/list"))
def list_command(bot, accid, event):
    msg = event.msg
    resources = database.get_resources(msg.chat_id)
    if not resources:
        _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text="ℹ️ No monitored resources in this chat. Add one with `/add <target>`."))
        return
        
    now_ts = int(time.time())
    reply = "⚙️ **Monitored Resources:**\n\n"
    for r in resources:
        m_until = r.get("maintenance_until") or 0
        is_maintenance = (now_ts < m_until)

        if is_maintenance:
            emoji_status = "⏸️"
            m_left_secs = m_until - now_ts
            m_left_str = format_duration(m_left_secs)
            status_text = f"PAUSED ({m_left_str} left)"
        elif r["status"] == "up":
            emoji_status = "🟢"
            status_text = "UP"
        elif r["status"] == "down":
            emoji_status = "🔴"
            status_text = "DOWN"
        else:
            emoji_status = "⚪"
            status_text = "UNKNOWN"
            
        uptime = database.get_resource_uptime_30d(r["id"])
        
        extra_info = ""
        if r.get("last_latency_ms") is not None:
            extra_info += f" | ⚡ `{r['last_latency_ms']}ms`"
        if r.get("expected_keyword"):
            extra_info += f" | 🔍 \"{r['expected_keyword']}\""
            
        ssl_info = ""
        if r.get("url", "").startswith("https://"):
            exp_ts = r.get("ssl_expiry_date")
            if exp_ts:
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
            f"  Uptime 30d: `{uptime:.2f}%` | Status: `{status_text}`{extra_info}{ssl_info}\n\n"
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

def _get_self_addr(bot, accid) -> str:
    try:
        addr = bot.rpc.get_config(accid, "configured_addr") or bot.rpc.get_config(accid, "addr")
        if isinstance(addr, str):
            return addr
        return ""
    except Exception:
        return ""

# Peer administration commands
@dc_cli.on(events.NewMessage(command="/nodename"))
def nodename_command(bot, accid, event):
    msg = event.msg
    if not _is_dc_admin(bot, accid, msg.from_id):
        _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text="❌ This command is only for the administrator."))
        return
    payload = (event.payload or "").strip()
    if payload:
        database.set_local_node_name(payload)
        _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text=f"✅ Local probe node name set to: `{payload}`"))
    else:
        current_name = database.get_local_node_name()
        _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text=f"📍 Current local probe node name: `{current_name}`\n\nTo change it: `/nodename <name>` (e.g. `/nodename Frankfurt-DE`, `/nodename RU-Moscow`)."))

@dc_cli.on(events.NewMessage(command="/peers"))
@dc_cli.on(events.NewMessage(command="/probes"))
def peers_command(bot, accid, event):
    msg = event.msg
    if not _is_dc_admin(bot, accid, msg.from_id):
        _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text="❌ This command is only for the administrator."))
        return
    peers = database.get_all_peers()
    local_node = database.get_local_node_name()
    
    # Statistics
    all_resources = database.get_all_resources()
    unique_local_urls = len(set(r["url"] for r in all_resources if r.get("url")))
    probe_targets = database.get_active_probe_targets()
    all_peer_measurements = database.get_all_peer_measurements()

    reply = f"🛰️ **Distributed Monitoring Peers**\n"
    reply += f"📍 Local Node: `{local_node}`\n\n"
    reply += f"📊 **Network Stats:**\n"
    reply += f"• Local Monitored Targets: `{unique_local_urls}` unique URLs (`{len(all_resources)}` across chats)\n"
    reply += f"• Mirrored Remote Probe Targets: `{len(probe_targets)}`\n"
    reply += f"• Cached Remote Measurements: `{len(all_peer_measurements)}`\n\n"

    if not peers:
        reply += (
            "_No remote peers configured._\n\n"
            "To link another Delta Chat Uptime bot as a remote probe:\n"
            "1. Run `/invitepeer` on the other bot to get its invite link.\n"
            "2. Run `/addpeer <link> [node_name]` on this bot."
        )
    else:
        reply += f"🔗 **Connected Probes ({len(peers)}):**\n"
        now = int(time.time())
        for p in peers:
            last_seen = p.get("last_seen")
            if not last_seen or last_seen == 0:
                seen_str = "Never"
                status_icon = "⚪"
            else:
                diff = max(1, now - last_seen)
                if diff < 300:
                    status_icon = "🟢"
                    seen_str = f"{diff}s ago" if diff < 60 else f"{diff // 60}m ago"
                elif diff < 3600:
                    status_icon = "🟡"
                    seen_str = f"{diff // 60}m ago"
                else:
                    status_icon = "🔴"
                    seen_str = f"{diff // 3600}h ago"
            chat_lbl = f"Chat ID: `{p.get('chat_id')}`" if p.get('chat_id') else "Chat: `Pending`"
            p_node = p.get('node_name') or 'Remote'
            node_meas_count = sum(1 for m in all_peer_measurements if m.get("node_name") == p_node)
            reply += f"• {status_icon} **{p_node}** — `{p['email']}`\n  {chat_lbl} | Last seen: `{seen_str}` | Active metrics: `{node_meas_count}`\n\n"
        reply += "Commands:\n• `/invitepeer` — Generate E2EE invite link\n• `/addpeer <email|link> [node_name]`\n• `/rmpeer <email>`\n• `/nodename <name>`\n• `/probeignore [url]` — Exclude/list ignored targets on this node\n• `/probeunignore <url>` — Resume probing target on this node"
    _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text=reply.strip()))

@dc_cli.on(events.NewMessage(command="/invitepeer"))
@dc_cli.on(events.NewMessage(command="/peerinvite"))
def invitepeer_command(bot, accid, event):
    msg = event.msg
    if not _is_dc_admin(bot, accid, msg.from_id):
        _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text="❌ This command is only for the administrator."))
        return
    try:
        qr_link = bot.rpc.get_chat_securejoin_qr_code(accid, None)
        node_name = database.get_local_node_name()
        addr = bot.rpc.get_config(accid, "configured_addr") or bot.rpc.get_config(accid, "addr")
        
        reply = (
            f"🔗 **Peering Invite Link (E2E Encrypted SecureJoin)**\n\n"
            f"Local Node: **{node_name}** (`{addr}`)\n\n"
            f"To link this bot to another Delta Chat Uptime bot:\n"
            f"1. Copy this command:\n"
            f"`/addpeer {qr_link} {node_name}`\n\n"
            f"2. Send it to your other bot (in private chat)."
        )
        _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text=reply))
    except Exception as e:
        _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text=f"❌ Failed to generate invite link: {e}"))

@dc_cli.on(events.NewMessage(command="/addpeer"))
def addpeer_command(bot, accid, event):
    msg = event.msg
    if not _is_dc_admin(bot, accid, msg.from_id):
        _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text="❌ This command is only for the administrator."))
        return
    payload = (event.payload or "").strip()
    if not payload:
        _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(
            text="Usage:\n"
                 "• Via SecureJoin Invite Link (Recommended for Chatmail/Strict E2EE):\n"
                 "  `/addpeer https://i.delta.chat/#... [node_name]`\n"
                 "• Via Email Address:\n"
                 "  `/addpeer user@example.com [node_name]`\n\n"
                 "💡 Tip: Use `/invitepeer` on your other bot to generate a SecureJoin invite link."
        ))
        return
    parts = payload.split(maxsplit=1)
    target = parts[0].strip()
    node_name = parts[1].strip() if len(parts) > 1 else "Remote-Node"
    
    if "i.delta.chat" in target or target.startswith("OPENPGP4FPR:") or target.startswith("DCACCOUNT:"):
        try:
            # SecureJoin flow for strict E2EE
            qr_info = bot.rpc.check_qr(accid, target)
            chat_id = bot.rpc.secure_join(accid, target)
            
            peer_email = ""
            if isinstance(qr_info, dict):
                peer_email = qr_info.get("address") or qr_info.get("text") or ""
                if not peer_email and qr_info.get("contact_id"):
                    try:
                        c = bot.rpc.get_contact(accid, qr_info["contact_id"])
                        peer_email = getattr(c, 'address', '') or (c.get('address') if isinstance(c, dict) else '')
                    except Exception:
                        pass
                        
            if not peer_email and chat_id:
                try:
                    contacts = bot.rpc.get_chat_contacts(accid, chat_id)
                    for cid in contacts:
                        if cid != 1:
                            c = bot.rpc.get_contact(accid, cid)
                            peer_email = getattr(c, 'address', '') or (c.get('address') if isinstance(c, dict) else '')
                            break
                except Exception:
                    pass
                    
            if not peer_email:
                peer_email = f"peer_{chat_id}@securejoin"
                
            database.add_or_update_peer(peer_email, node_name, chat_id)
            
            self_addr = _get_self_addr(bot, accid)
            hello_payload = {
                "node_name": database.get_local_node_name(),
                "sender_email": self_addr,
                "version": VERSION
            }
            hello_text = f"[UPTIME_PEER_HELLO]\n{json.dumps(hello_payload)}\n[/UPTIME_PEER_HELLO]"
            _dc_send_msg_with_stats(bot, accid, chat_id, MsgData(text=hello_text))
            
            _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(
                text=f"✅ SecureJoin E2EE established with **{node_name}** (`{peer_email}`).\nChat ID: `{chat_id}`."
            ))
        except Exception as e:
            _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text=f"❌ Failed to process SecureJoin invite: {e}"))
        return
        
    # Email address flow
    email = target.lower()
    if "@" not in email or "." not in email:
        _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text="❌ Invalid email address or invite link."))
        return
        
    try:
        contact_id = bot.rpc.create_contact(accid, email, node_name)
        chat_id = bot.rpc.create_chat_by_contact_id(accid, contact_id)
        database.add_or_update_peer(email, node_name, chat_id)
        
        self_addr = _get_self_addr(bot, accid)
        hello_payload = {
            "node_name": database.get_local_node_name(),
            "sender_email": self_addr,
            "version": VERSION
        }
        hello_text = f"[UPTIME_PEER_HELLO]\n{json.dumps(hello_payload)}\n[/UPTIME_PEER_HELLO]"
        _dc_send_msg_with_stats(bot, accid, chat_id, MsgData(text=hello_text))
        
        _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(
            text=f"✅ Peer `{email}` (**{node_name}**) added.\nSent peering handshake via private chat (Chat ID: `{chat_id}`).\n\n"
                 f"💡 _Note: If your provider requires strict E2EE (e.g. chatmail), generate an invite on the other bot with `/invitepeer` and add it via `/addpeer <link>`._"
        ))
    except Exception as e:
        _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text=f"❌ Failed to add peer: {e}"))

@dc_cli.on(events.NewMessage(command="/rmpeer"))
def rmpeer_command(bot, accid, event):
    msg = event.msg
    if not _is_dc_admin(bot, accid, msg.from_id):
        _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text="❌ This command is only for the administrator."))
        return
    email = (event.payload or "").strip().lower()
    if not email:
        _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text="Usage: `/rmpeer <email>`"))
        return
    removed = database.remove_peer(email)
    if removed:
        _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text=f"✅ Peer `{email}` removed."))
    else:
        _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text=f"❌ Peer `{email}` not found in database."))

@dc_cli.on(events.NewMessage(command="/probeignore"))
@dc_cli.on(events.NewMessage(command="/ignoreprobe"))
def probeignore_command(bot, accid, event):
    msg = event.msg
    if not _is_dc_admin(bot, accid, msg.from_id):
        _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text="❌ This command is only for the administrator."))
        return
    url = (event.payload or "").strip()
    local_node = database.get_local_node_name()
    if not url:
        ignored = database.get_all_ignored_probe_targets()
        if not ignored:
            _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(
                text=f"ℹ️ No ignored probe targets configured on `{local_node}`.\n\nTo ignore an inaccessible or region-blocked target on this probe:\n`/probeignore <url>`"
            ))
            return
        reply = f"🚫 **Ignored Probe Targets on `{local_node}` ({len(ignored)}):**\n\n"
        for item in ignored:
            reply += f"• `{item['url']}`\n"
        reply += "\nTo unignore and resume monitoring on this probe: `/probeunignore <url>`"
        _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text=reply))
        return

    if not url.startswith(("http://", "https://", "tcp://", "ping://")) and ":" not in url:
        if "." in url:
            url = f"https://{url}"
    database.add_ignored_probe_target(url)
    _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(
        text=f"✅ Target `{url}` is now **ignored** on `{local_node}`.\nIt will not be scanned by this probe or synced to peer dashboards."
    ))

@dc_cli.on(events.NewMessage(command="/probeunignore"))
@dc_cli.on(events.NewMessage(command="/unignoreprobe"))
def probeunignore_command(bot, accid, event):
    msg = event.msg
    if not _is_dc_admin(bot, accid, msg.from_id):
        _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text="❌ This command is only for the administrator."))
        return
    url = (event.payload or "").strip()
    if not url:
        _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text="Usage: `/probeunignore <url>`"))
        return

    removed = database.remove_ignored_probe_target(url)
    if not removed and not url.startswith(("http://", "https://")):
        removed = database.remove_ignored_probe_target(f"https://{url}")
        if removed:
            url = f"https://{url}"

    local_node = database.get_local_node_name()
    if removed:
        _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(
            text=f"✅ Target `{url}` removed from probe ignore list on `{local_node}`.\nIt will resume being scanned upon the next peer sync."
        ))
    else:
        _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(
            text=f"❌ Target `{url}` was not found in the ignored probe list on `{local_node}`."
        ))

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
    setup_custom_command_parser(bot)
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

def _record_peer_activity(sender_addr: str):
    if not sender_addr:
        return
    was_offline, downtime_sec, peer_data = database.update_peer_last_seen(sender_addr)
    if was_offline and peer_data:
        p_node = peer_data.get("node_name") or "Remote"
        p_email = peer_data.get("email")
        dt_str = format_duration(downtime_sec)
        rec_txt = (
            f"✅ **Monitoring Probe Restored**\n"
            f"Probe Node: 🛰️ **{p_node}** (`{p_email}`)\n"
            f"Downtime: `{dt_str}`\n\n"
            f"🟢 Probe is back online and actively exchanging distributed telemetry."
        )
        if async_event_loop and async_event_loop.is_running():
            asyncio.run_coroutine_threadsafe(send_admin_notification(rec_txt), async_event_loop)

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

    # 1. Peer Handshake: HELLO
    if "[UPTIME_PEER_HELLO]" in text and "[/UPTIME_PEER_HELLO]" in text:
        try:
            start_idx = text.find("[UPTIME_PEER_HELLO]") + len("[UPTIME_PEER_HELLO]")
            end_idx = text.find("[/UPTIME_PEER_HELLO]")
            hello_data = json.loads(text[start_idx:end_idx].strip())
            peer_node = hello_data.get("node_name") or "Remote-Node"
            sender_addr = hello_data.get("sender_email")
            if not sender_addr:
                try:
                    contact = bot.rpc.get_contact(accid, msg.from_id)
                    sender_addr = getattr(contact, 'address', '') or (contact.get('address') if isinstance(contact, dict) else '')
                except Exception:
                    pass
            if sender_addr:
                database.add_or_update_peer(sender_addr, peer_node, msg.chat_id, int(time.time()))
                _record_peer_activity(sender_addr)

            self_addr = _get_self_addr(bot, accid)
            ack_payload = {
                "node_name": database.get_local_node_name(),
                "sender_email": self_addr,
                "version": VERSION
            }
            ack_msg = f"[UPTIME_PEER_HELLO_ACK]\n{json.dumps(ack_payload)}\n[/UPTIME_PEER_HELLO_ACK]"
            _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text=ack_msg))
        except Exception as e:
            logger.error(f"Error handling peer hello: {e}")
        return

    # 2. Peer Handshake: HELLO_ACK
    if "[UPTIME_PEER_HELLO_ACK]" in text and "[/UPTIME_PEER_HELLO_ACK]" in text:
        try:
            start_idx = text.find("[UPTIME_PEER_HELLO_ACK]") + len("[UPTIME_PEER_HELLO_ACK]")
            end_idx = text.find("[/UPTIME_PEER_HELLO_ACK]")
            ack_data = json.loads(text[start_idx:end_idx].strip())
            peer_node = ack_data.get("node_name") or "Remote-Node"
            sender_addr = ack_data.get("sender_email")
            if not sender_addr:
                try:
                    contact = bot.rpc.get_contact(accid, msg.from_id)
                    sender_addr = getattr(contact, 'address', '') or (contact.get('address') if isinstance(contact, dict) else '')
                except Exception:
                    pass
            if sender_addr:
                database.add_or_update_peer(sender_addr, peer_node, msg.chat_id, int(time.time()))
                _record_peer_activity(sender_addr)
        except Exception as e:
            logger.error(f"Error handling peer hello ack: {e}")
        return

    # 3. Peer Cross-Check Request (Instant verification)
    if "[UPTIME_PEER_CHECK_REQ]" in text and "[/UPTIME_PEER_CHECK_REQ]" in text:
        try:
            start_idx = text.find("[UPTIME_PEER_CHECK_REQ]") + len("[UPTIME_PEER_CHECK_REQ]")
            end_idx = text.find("[/UPTIME_PEER_CHECK_REQ]")
            req_data = json.loads(text[start_idx:end_idx].strip())
            req_id = req_data.get("req_id")
            target_url = req_data.get("url")
            check_type = req_data.get("type", "http")
            keyword = req_data.get("expected_keyword")
            peer_node = req_data.get("node_name") or "Peer"

            try:
                contact = bot.rpc.get_contact(accid, msg.from_id)
                sender_addr = getattr(contact, 'address', '') or (contact.get('address') if isinstance(contact, dict) else '')
                if sender_addr:
                    database.add_or_update_peer(sender_addr, peer_node, msg.chat_id, int(time.time()))
                    _record_peer_activity(sender_addr)
            except Exception:
                pass

            if req_id and target_url:
                synth_r = {
                    "id": 0,
                    "url": target_url,
                    "type": check_type,
                    "expected_keyword": keyword
                }
                async def _do_cross_check_reply():
                    res = await run_single_check(synth_r)
                    if len(res) == 3:
                        is_up, error_msg, latency_ms = res
                    else:
                        is_up, error_msg = res
                        latency_ms = None
                    resp_payload = {
                        "req_id": req_id,
                        "url": target_url,
                        "status": "up" if is_up else "down",
                        "latency_ms": latency_ms,
                        "error_msg": error_msg,
                        "node_name": database.get_local_node_name()
                    }
                    resp_msg = f"[UPTIME_PEER_CHECK_RESP]\n{json.dumps(resp_payload)}\n[/UPTIME_PEER_CHECK_RESP]"
                    _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text=resp_msg))

                if async_event_loop and async_event_loop.is_running():
                    asyncio.run_coroutine_threadsafe(_do_cross_check_reply(), async_event_loop)
                else:
                    try:
                        loop = asyncio.get_event_loop()
                        loop.create_task(_do_cross_check_reply())
                    except Exception:
                        asyncio.run(_do_cross_check_reply())
        except Exception as e:
            logger.error(f"Error processing peer check request: {e}")
        return

    # 4. Peer Cross-Check Response
    if "[UPTIME_PEER_CHECK_RESP]" in text and "[/UPTIME_PEER_CHECK_RESP]" in text:
        try:
            start_idx = text.find("[UPTIME_PEER_CHECK_RESP]") + len("[UPTIME_PEER_CHECK_RESP]")
            end_idx = text.find("[/UPTIME_PEER_CHECK_RESP]")
            resp_data = json.loads(text[start_idx:end_idx].strip())
            req_id = resp_data.get("req_id")
            target_url = resp_data.get("url")
            status = resp_data.get("status", "unknown")
            latency_ms = resp_data.get("latency_ms")
            error_msg = resp_data.get("error_msg")
            node_name = resp_data.get("node_name") or "Remote-Node"

            if target_url:
                database.save_peer_measurement(target_url, node_name, status, latency_ms, error_msg, int(time.time()))

            try:
                contact = bot.rpc.get_contact(accid, msg.from_id)
                sender_addr = getattr(contact, 'address', '') or (contact.get('address') if isinstance(contact, dict) else '')
                if sender_addr:
                    _record_peer_activity(sender_addr)
            except Exception:
                pass

            if req_id and req_id in pending_peer_checks:
                fut, expected_count, resp_list = pending_peer_checks[req_id]
                resp_list.append(resp_data)
                if len(resp_list) >= expected_count and not fut.done():
                    fut.set_result(resp_list)
        except Exception as e:
            logger.error(f"Error handling peer check response: {e}")
        return

    # 5. Peer Telemetry Batch
    if "[UPTIME_PEER_METRICS]" in text and "[/UPTIME_PEER_METRICS]" in text:
        try:
            start_idx = text.find("[UPTIME_PEER_METRICS]") + len("[UPTIME_PEER_METRICS]")
            end_idx = text.find("[/UPTIME_PEER_METRICS]")
            metrics_data = json.loads(text[start_idx:end_idx].strip())
            peer_node = metrics_data.get("node_name") or "Remote-Node"
            metrics_list = metrics_data.get("metrics", [])
            sender_addr = metrics_data.get("sender_email")
            if not sender_addr:
                try:
                    contact = bot.rpc.get_contact(accid, msg.from_id)
                    sender_addr = getattr(contact, 'address', '') or (contact.get('address') if isinstance(contact, dict) else '')
                except Exception:
                    pass
            if sender_addr:
                _record_peer_activity(sender_addr)

            if metrics_list:
                # 1. Save measurements reported from peer to show on web dashboard
                database.save_peer_measurements_batch(peer_node, metrics_list)
                # 2. Mirror targets to local probe queue so this node monitors them too!
                database.save_probe_targets_batch(metrics_list, sender_addr or peer_node)
        except Exception as e:
            logger.error(f"Error handling peer metrics: {e}")
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

"""Tells a blocked HTTP(S) target from a broken one, so an alert can say why a node cannot reach it.

A failed check only says "Timeout" or "Connection reset". Filtering leaves traces that a broken
server does not, and each one is found by comparing two probes made from this node:

* DNS spoofing: the system resolver answers other addresses than public resolvers (1.1.1.1, 8.8.8.8),
  the address from the public resolvers works (for https: the certificate is valid for the name) and the
  one from the system resolver does not.
* SNI filtering (https): a TLS handshake with the real name is reset or hangs, while a handshake with
  the same address and no name (or a neutral one) gets an answer. The server is alive; the name is cut.
* Host filtering (http): the same with the Host header of a plain request.

Nothing here decides up or down. The result is a short tag ("SNI block?") put in front of the error,
and the vote lines show it next to the node that saw it. When both probes fail, the address itself is
unreachable (a dead server or a block by IP) and no tag is given: the votes of the other nodes say
which of the two it is. The question mark stays because a heuristic is not proof.
"""
import asyncio
import ipaddress
import logging
import os
import re
import ssl
import time
import weakref

try:
    import aiodns
except ImportError:  # the bot runs without it (system resolver only), so does this module
    aiodns = None

logger = logging.getLogger("deltachat_uptime.blockcheck")

ENABLED = os.environ.get("BLOCKCHECK", "1").strip().lower() not in ("0", "false", "no", "off")
PUBLIC_RESOLVERS = [r.strip() for r in os.environ.get("BLOCKCHECK_RESOLVERS", "1.1.1.1,8.8.8.8").split(",") if r.strip()]

PROBE_TIMEOUT = 4.0       # one probe: connect + handshake / first reply
DEADLINE = 10.0           # whole diagnosis of one target
CACHE_TTL = 300.0         # a failing target is checked every interval; diagnose it once per 5 minutes
CACHE_MAX = 512
MAX_PARALLEL = 8          # diagnoses at once, so a mass outage does not open a flood of sockets
CONTROL_SNI = "example.com"
CONTROL_HOST = "example.com"

# What one probe saw
ANSWER = "answer"     # the peer spoke: a TLS handshake or alert, or an HTTP reply
BADCERT = "badcert"   # TLS answered, but the certificate does not belong to the name
RESET = "reset"       # connection reset or closed without an answer
TIMEOUT = "timeout"   # no answer within PROBE_TIMEOUT
NOCONNECT = "noconnect"  # TCP did not connect (refused, unreachable, timeout)

TAG_DNS = "DNS spoofing?"
TAG_SNI = "SNI block?"
TAG_HOST = "HTTP Host block?"
TAG_FREEZE = "Freeze?"   # set by the check itself (bot._read_body_limited), not by diagnose()
TAGS = (TAG_DNS, TAG_SNI, TAG_HOST, TAG_FREEZE)
_TAG_RE = re.compile(r"^(" + "|".join(re.escape(t) for t in TAGS) + r") (.*)$", re.S)


def split_tag(error):
    """'SNI block? Timeout' -> ('SNI block?', 'Timeout'); an error without a tag -> (None, error)."""
    m = _TAG_RE.match(error or "")
    return (m.group(1), m.group(2)) if m else (None, error)


def with_tag(tag, error):
    return f"{tag} {error}" if tag else error


async def probe_tls(ip: str, port: int, sni: str | None, timeout: float = PROBE_TIMEOUT, verify_name: str | None = None) -> str:
    """TLS handshake with ip:port, announcing sni (None: no server name at all).

    verify_name: also check the certificate against the system CAs and this name (-> BADCERT)."""
    ctx = ssl.create_default_context()
    if verify_name is None:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    loop = asyncio.get_running_loop()
    writer = None
    try:
        async with asyncio.timeout(timeout):
            try:
                reader, writer = await asyncio.open_connection(ip, port)
            except (OSError, asyncio.TimeoutError) as e:
                if isinstance(e, ConnectionResetError):
                    return RESET
                return NOCONNECT
            try:
                transport = await loop.start_tls(
                    writer.transport, writer.transport.get_protocol(), ctx,
                    server_hostname=verify_name or sni, server_side=False)
            except ssl.SSLCertVerificationError:
                return BADCERT
            except ssl.SSLEOFError:
                return RESET
            except ssl.SSLError as e:
                # An alert (handshake_failure, unrecognized_name...) or a non-TLS reply is an answer
                return RESET if "EOF" in str(e).upper() else ANSWER
            except (ConnectionError, BrokenPipeError):
                return RESET
            transport.close()
            writer = None
            return ANSWER
    except asyncio.TimeoutError:
        return TIMEOUT
    except Exception as e:
        logger.debug(f"TLS probe of {ip}:{port} failed unexpectedly: {e!r}")
        return RESET if isinstance(e, ConnectionError) else NOCONNECT
    finally:
        if writer is not None:
            writer.transport.abort()


async def probe_http(ip: str, port: int, host_header: str, timeout: float = PROBE_TIMEOUT) -> str:
    """One plain GET / with the given Host header; ANSWER if anything comes back."""
    writer = None
    try:
        async with asyncio.timeout(timeout):
            try:
                reader, writer = await asyncio.open_connection(ip, port)
            except ConnectionResetError:
                return RESET
            except OSError:
                return NOCONNECT
            request = f"GET / HTTP/1.1\r\nHost: {host_header}\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n"
            try:
                writer.write(request.encode("ascii", "ignore"))
                await writer.drain()
                data = await reader.read(64)
            except (ConnectionError, BrokenPipeError):
                return RESET
            return ANSWER if data else RESET
    except asyncio.TimeoutError:
        return TIMEOUT
    except Exception as e:
        logger.debug(f"HTTP probe of {ip}:{port} failed unexpectedly: {e!r}")
        return NOCONNECT
    finally:
        if writer is not None:
            writer.transport.abort()


_resolvers = weakref.WeakKeyDictionary()  # event loop -> long-lived aiodns resolver (see bot._get_aiodns_resolver)


def _public_resolver():
    loop = asyncio.get_running_loop()
    resolver = _resolvers.get(loop)
    if resolver is None:
        resolver = aiodns.DNSResolver(nameservers=PUBLIC_RESOLVERS, loop=loop, timeout=2.0, tries=1)
        _resolvers[loop] = resolver
    return resolver


async def resolve_public(host: str) -> list[str]:
    """Public IPv4 addresses of host according to the public resolvers ([] if unknown)."""
    if aiodns is None or not PUBLIC_RESOLVERS:
        return []
    try:
        records = await _public_resolver().query(host, "A")
    except Exception as e:
        logger.debug(f"Public DNS lookup of {host} failed: {e!r}")
        return []
    ips = []
    for rec in records:
        try:
            if ipaddress.ip_address(rec.host).is_global:   # never connect to what a resolver says is internal
                ips.append(rec.host)
        except ValueError:
            continue
    return ips


async def _real_probe(ip: str, port: int, host: str, use_tls: bool, verify: bool = False) -> str:
    if use_tls:
        return await probe_tls(ip, port, host, verify_name=host if verify else None)
    return await probe_http(ip, port, host)


async def _control_probe(ip: str, port: int, use_tls: bool) -> str:
    """The same address without the real name; the best answer of the neutral probes counts."""
    if use_tls:
        results = await asyncio.gather(probe_tls(ip, port, None), probe_tls(ip, port, CONTROL_SNI))
    else:
        results = [await probe_http(ip, port, CONTROL_HOST)]
    return ANSWER if ANSWER in results else results[0]


async def diagnose(host: str, port: int, use_tls: bool, system_ips: list[str]) -> str | None:
    """TAG_DNS / TAG_SNI / TAG_HOST, or None when nothing points at filtering."""
    ips = [ip for ip in system_ips if ":" not in ip] or list(system_ips)   # IPv4 first, like the checks
    if not ips:
        return None
    sys_ip = ips[0]

    public = await resolve_public(host)
    if public and not (set(public) & set(system_ips)):
        sys_result, pub_result = await asyncio.gather(
            _real_probe(sys_ip, port, host, use_tls, verify=True),
            _real_probe(public[0], port, host, use_tls, verify=True))
        if pub_result == ANSWER and sys_result != ANSWER:
            return TAG_DNS

    real, control = await asyncio.gather(_real_probe(sys_ip, port, host, use_tls), _control_probe(sys_ip, port, use_tls))
    if real in (RESET, TIMEOUT) and control == ANSWER:
        return TAG_SNI if use_tls else TAG_HOST
    return None


_cache: dict = {}
_slots = None
_slots_loop = None


def _semaphore() -> asyncio.Semaphore:
    global _slots, _slots_loop
    loop = asyncio.get_running_loop()
    if _slots is None or _slots_loop is not loop:
        _slots, _slots_loop = asyncio.Semaphore(MAX_PARALLEL), loop
    return _slots


async def diagnose_cached(host: str, port: int, use_tls: bool, system_ips: list[str]) -> str | None:
    """diagnose() with a 5 minute memory per target, a parallel limit and an overall deadline; never raises."""
    if not ENABLED:
        return None
    key = (host.lower(), port, use_tls, tuple(sorted(system_ips)))
    now = time.monotonic()
    hit = _cache.get(key)
    if hit and hit[0] > now:
        return hit[1]
    try:
        async with _semaphore():
            async with asyncio.timeout(DEADLINE):
                tag = await diagnose(host, port, use_tls, system_ips)
    except Exception as e:   # includes TimeoutError: no answer is no tag
        logger.debug(f"Block diagnosis of {host}:{port} failed: {e!r}")
        tag = None
    if len(_cache) >= CACHE_MAX:
        for k in [k for k, v in _cache.items() if v[0] <= now] or list(_cache)[:CACHE_MAX // 4]:
            _cache.pop(k, None)
    _cache[key] = (now + CACHE_TTL, tag)
    return tag

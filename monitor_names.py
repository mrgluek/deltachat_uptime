"""Compact monitor labels shared by messages and the event journal."""
from urllib.parse import urlsplit
import re


def short_monitor_name(resource):
    name = str(resource.get("name") or "").strip()
    if not name or name.lower().startswith(("http://", "https://")):
        url = name or str(resource.get("url") or "")
        try:
            parsed = urlsplit(url if "://" in url else "//" + url)
            name = parsed.hostname or "Monitor"
            if ":" in name:
                name = "[" + name + "]"
            if parsed.port is not None:
                name += ":" + str(parsed.port)
        except ValueError:
            name = "Monitor"
    name = " ".join(name.split()) or "Monitor"
    return name if len(name) <= 30 else name[:29] + "…"


def short_journal_text(text, resources=()):
    """Also compact stored entries written by previous versions."""
    # Old journal entries saved node names but no historical voter denominator.
    text = re.sub(r" \(nodes: .*?(?:\)|$)", "", text)
    for resource in sorted(resources, key=lambda r: len(r.get("name") or r.get("url") or ""), reverse=True):
        old = resource.get("name") or resource.get("url")
        if old:
            text = text.replace(old, short_monitor_name(resource))
    text = re.sub(r'https?://[^\s,]+', lambda m: short_monitor_name({"url": m[0]}), text)
    # Historical monitor labels can outlive their resource (removal or rename).
    for prefix in ("➕ Added monitor ", "➖ Removed monitor ", "✏️ Changed monitor ",
                   "⏸️ Paused monitor ", "▶️ Resumed monitor "):
        if text.startswith(prefix):
            return prefix + short_monitor_name({"name": text[len(prefix):]})
    if text.startswith("✏️ Renamed monitor "):
        labels = text[len("✏️ Renamed monitor "):].split(" to ", 1)
        return "✏️ Renamed monitor " + " to ".join(short_monitor_name({"name": label}) for label in labels)
    for prefix in ("🔴 ", "🟠 ", "✅ "):
        if text.startswith(prefix):
            match = re.match(r"(.+?)( is (?:partially )?down| recovered after .*)", text[len(prefix):])
            if match:
                text = prefix + short_monitor_name({"name": match[1]}) + text[len(prefix) + len(match[1]):]
            break
    return text

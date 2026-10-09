"""Restricted, unauthenticated public-share importer; never a general URL fetcher."""

from __future__ import annotations

import asyncio
import ipaddress
import json
import re
import socket
import threading
from html.parser import HTMLParser

import httpx
from fastapi import HTTPException

HOST = "chatgpt.com"
MAX_RESPONSE_BYTES = 2 * 1024 * 1024
MAX_TEXT_BYTES = 128 * 1024
MAX_SCRIPT_BYTES = 512 * 1024
MAX_SCRIPT_CANDIDATES = 64
TOTAL_TIMEOUT = 15.0
SHARE_RE = re.compile(
    r"https://chatgpt\.com/share/"
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z"
)


def validate_share_url(value: str | None) -> str:
    if not isinstance(value, str) or not SHARE_RE.fullmatch(value):
        raise ValueError("Expected a canonical https://chatgpt.com/share/<UUID> URL")
    return value


def unsupported():
    return HTTPException(
        422,
        "Public shared conversation is unavailable or unsupported. "
        "Paste the conversation text instead.",
    )


class ShareHTML(HTMLParser):
    """Only role-marked conversation containers supply visible HTML text."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.stack = []
        self.messages = []
        self.scripts = []
        self.current = None
        self.script = None
        self.script_is_json = False
        self.hidden_depths = []
        self.title = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag in {"br", "hr", "img", "input", "meta", "link", "wbr", "source"}:
            if tag == "br" and self.current:
                self.current[1].append("\n")
            return
        self.stack.append(tag)
        if (
            "hidden" in attrs
            or attrs.get("aria-hidden") == "true"
            or re.search(
                r"(?:display\s*:\s*none|visibility\s*:\s*hidden)",
                attrs.get("style", ""),
                re.IGNORECASE,
            )
        ):
            self.hidden_depths.append(len(self.stack))
        if tag == "script":
            self.script = []
            self.script_is_json = attrs.get("type", "").split(";", 1)[
                0
            ].strip().casefold() == "application/json" or attrs.get(
                "id", ""
            ).casefold() in {"__next_data__", "__next_f"}
        role = attrs.get("data-message-author-role")
        if role is None and tag == "article":
            label = attrs.get("aria-label", "").casefold()
            if label.startswith(("you said", "user said")):
                role = "user"
            elif label.startswith(("chatgpt said", "assistant said")):
                role = "assistant"
        if (
            role in {"user", "assistant"}
            and self.current is None
            and not self.hidden_depths
        ):
            self.current = (role, [], len(self.stack))

    def handle_endtag(self, tag):
        if tag == "script" and self.script is not None:
            self.scripts.append(("".join(self.script), self.script_is_json))
            self.script = None
        if tag not in self.stack:
            return
        index = len(self.stack) - 1 - self.stack[::-1].index(tag)
        if self.current and index < self.current[2]:
            role, parts, _ = self.current
            text = "".join(parts).strip()
            if text:
                self.messages.append((role, text))
            self.current = None
        del self.stack[index:]
        self.hidden_depths = [depth for depth in self.hidden_depths if depth <= index]

    def handle_data(self, data):
        if "title" in self.stack:
            self.title.append(data)
        if self.script is not None:
            self.script.append(data)
        elif (
            self.current
            and not self.hidden_depths
            and not any(
                tag in {"style", "nav", "footer", "button", "noscript"}
                for tag in self.stack
            )
        ):
            self.current[1].append(data)


def _inflate(table):
    """Decode bounded Remix/turbo-stream reference tables, without executing JS."""
    if not isinstance(table, list) or not table:
        return table

    budget = 50000

    def resolve(value, active, depth):
        nonlocal budget
        budget -= 1
        if depth > 40 or budget < 0:
            raise ValueError("Unsupported reference table")
        if type(value) is int:
            if value < 0:
                return None
            if value >= len(table) or value in active:
                raise ValueError("Unsupported reference table")
            return resolve(table[value], active | {value}, depth + 1)
        if isinstance(value, dict):
            result = {}
            for key, child in value.items():
                if key.startswith("_") and key[1:].isdigit():
                    key = resolve(int(key[1:]), active, depth + 1)
                if isinstance(key, str):
                    result[key] = resolve(child, active, depth + 1)
            return result
        if isinstance(value, list):
            return [resolve(child, active, depth + 1) for child in value]
        return value

    return resolve(0, set(), 0)


def _json_messages(value):
    messages = []
    visited = 0

    def visit(item, depth=0):
        nonlocal visited
        visited += 1
        if visited > 50000 or depth > 40:
            raise ValueError("Unsupported JSON structure")
        if isinstance(item, dict):
            author = item.get("author")
            role = author.get("role") if isinstance(author, dict) else item.get("role")
            content = item.get("content")
            if role in {"user", "assistant"}:
                if isinstance(content, dict) and content.get("content_type") == "text":
                    parts = content.get("parts", [])
                    text = "\n".join(p for p in parts if isinstance(p, str))
                elif isinstance(content, dict) and isinstance(
                    content.get("parts"), list
                ):
                    text = "\n".join(p for p in content["parts"] if isinstance(p, str))
                elif isinstance(content, dict) and isinstance(content.get("text"), str):
                    text = content["text"]
                elif isinstance(content, str):
                    text = content
                else:
                    text = ""
                if text.strip() and not item.get("metadata", {}).get(
                    "is_visually_hidden_from_conversation", False
                ):
                    messages.append((role, text.strip()))
                    return
            for child in item.values():
                visit(child, depth + 1)
        elif isinstance(item, list):
            for child in item:
                visit(child, depth + 1)

    visit(value)
    return messages


def _embedded_messages(source: str) -> list[tuple[str, str]]:
    """Extract narrowly shaped message objects without executing page scripts."""
    found: list[tuple[str, str]] = []
    role_pattern = re.compile(
        r'"(?:role|name)"\s*:\s*"(?P<role>user|assistant)"', re.IGNORECASE
    )
    decoder = json.JSONDecoder()
    for match in role_pattern.finditer(source):
        role = match.group("role").casefold()
        window = source[match.start() : match.start() + 20000]
        content_match = re.search(
            r'"(?:parts|text)"\s*:\s*(?P<value>\[.*?\]|"(?:\\.|[^"\\])*")',
            window,
            re.IGNORECASE | re.DOTALL,
        )
        if not content_match:
            continue
        try:
            value, _ = decoder.raw_decode(content_match.group("value"))
        except (ValueError, TypeError):
            continue
        if isinstance(value, list):
            text = "\n".join(item for item in value if isinstance(item, str))
        elif isinstance(value, str):
            text = value
        else:
            text = ""
        if text.strip():
            found.append((role, text.strip()))
    return found


def _script_candidates(script: str, is_json: bool):
    """Yield JSON values from recognized loader scripts, never execute script."""
    if len(script.encode("utf-8")) > MAX_SCRIPT_BYTES:
        return
    decoder = json.JSONDecoder()
    markers = list(
        re.finditer(
            r"(?:__reactRouterContext\.streamController\.enqueue|__next_f\.push)"
            r"\(\s*",
            script,
        )
    )
    if is_json:
        try:
            yield json.loads(script)
        except (ValueError, TypeError, RecursionError):
            pass
    for marker in markers:
        try:
            value, _ = decoder.raw_decode(script[marker.end() :])
        except (ValueError, TypeError, RecursionError):
            continue
        yield value
        # Loader payloads commonly contain a JSON document as an escaped string.
        if isinstance(value, str):
            try:
                yield json.loads(value)
            except (ValueError, TypeError, RecursionError):
                pass
        elif isinstance(value, list):
            for child in value:
                if isinstance(child, str) and child.lstrip().startswith(("{", "[")):
                    try:
                        yield json.loads(child)
                    except (ValueError, TypeError, RecursionError):
                        pass
    # application/json scripts may themselves contain a JSON string literal.
    # Decode literals rather than trying to interpret surrounding JavaScript.
    if is_json:
        for match in re.finditer(r'(?<!\\)"', script):
            try:
                value, _ = decoder.raw_decode(script[match.start() :])
            except (ValueError, TypeError, RecursionError):
                continue
            if isinstance(value, str) and value.lstrip().startswith(("{", "[")):
                try:
                    yield json.loads(value)
                except (ValueError, TypeError, RecursionError):
                    continue


def extract_conversation(html: str) -> str:
    parser = ShareHTML()
    try:
        parser.feed(html)
        title = "".join(parser.title).strip().casefold()
        if any(
            phrase in title
            for phrase in (
                "log in",
                "login",
                "sign in",
                "just a moment",
                "access denied",
                "verify you are human",
            )
        ):
            raise unsupported()
        # Visible markup is preferred to loader state (which can contain branches).
        messages = parser.messages
        if not messages:
            candidate_count = 0
            for script, is_json in parser.scripts:
                for candidate in _script_candidates(script, is_json):
                    candidate_count += 1
                    if candidate_count > MAX_SCRIPT_CANDIDATES:
                        break
                    try:
                        data = (
                            json.loads(candidate)
                            if isinstance(candidate, str)
                            else candidate
                        )
                        if isinstance(data, str):
                            data = json.loads(data)
                        found = _json_messages(data)
                        if not found and isinstance(data, list):
                            found = _json_messages(_inflate(data))
                        if not found and isinstance(data, list):
                            for child in data:
                                if isinstance(child, str):
                                    try:
                                        found = _json_messages(json.loads(child))
                                    except (ValueError, TypeError, RecursionError):
                                        continue
                                    if found:
                                        break
                        if found:
                            messages = found
                            break
                    except (ValueError, TypeError, AttributeError, RecursionError):
                        continue
                if messages:
                    break
        if not messages:
            script_source = "\n".join(
                script
                for script, is_json in parser.scripts
                if is_json
                or re.search(
                    r"(?:__reactRouterContext\.streamController\.enqueue|__next_f\.push)",
                    script,
                )
            )
            messages = _embedded_messages(script_source)
        if not messages or {role for role, _ in messages} != {"user", "assistant"}:
            raise unsupported()
        text = "\n\n".join(f"{role}: {text}" for role, text in messages)
        if len(text.encode("utf-8")) > MAX_TEXT_BYTES:
            raise HTTPException(
                422, "Shared conversation exceeds the import text limit"
            )
        return text
    except HTTPException:
        raise
    except (ValueError, UnicodeError, RecursionError):
        raise unsupported() from None


async def _dns_lookup():
    # libc DNS has no portable deadline. A daemon worker avoids asyncio.run's
    # default-executor shutdown waiting indefinitely after the overall timeout.
    loop = asyncio.get_running_loop()
    future = loop.create_future()

    def deliver(value, error):
        if not future.done():
            if error is None:
                future.set_result(value)
            else:
                future.set_exception(error)

    def lookup():
        try:
            value = socket.getaddrinfo(HOST, 443, type=socket.SOCK_STREAM)
            error = None
        except OSError as exc:
            value, error = None, exc
        try:
            loop.call_soon_threadsafe(deliver, value, error)
        except RuntimeError:
            pass  # The request timed out and its loop is already closed.

    threading.Thread(target=lookup, daemon=True).start()
    return await future


async def _resolve_public_ip():
    records = await _dns_lookup()
    try:
        addresses = [ipaddress.ip_address(record[4][0]) for record in records]
    except (ValueError, TypeError, IndexError):
        raise HTTPException(
            503, "Public share destination could not be verified"
        ) from None
    if not addresses or any(
        not address.is_global
        or address.is_multicast
        or address.is_reserved
        or getattr(address, "ipv4_mapped", None) is not None
        for address in addresses
    ):
        raise HTTPException(503, "Public share destination could not be verified")
    return str(addresses[0])


async def _fetch(url):
    address = await _resolve_public_ip()
    # Connect to the vetted literal IP; TLS certificate/SNI and Host remain fixed.
    # There is no second hostname lookup on the connection path (DNS rebinding).
    authority = f"[{address}]" if ":" in address else address
    target = f"https://{authority}{url[len('https://' + HOST) :]}"
    async with httpx.AsyncClient(
        trust_env=False,
        verify=True,
        follow_redirects=False,
        timeout=httpx.Timeout(5.0),
    ) as client:
        async with client.stream(
            "GET",
            target,
            headers={
                "Host": HOST,
                "Accept": "text/html",
                "Accept-Encoding": "identity",
            },
            extensions={"sni_hostname": HOST},
        ) as response:
            if response.status_code != 200:
                raise HTTPException(
                    502, "Public share retrieval was refused or unavailable"
                )
            if "text/html" not in response.headers.get("content-type", "").lower():
                raise unsupported()
            # Refuse compression rather than permitting a decompression bomb before
            # the decoded-size check. The server is explicitly asked for identity.
            if (
                response.headers.get("content-encoding", "identity").lower()
                != "identity"
            ):
                raise HTTPException(
                    502, "Public share response encoding is unsupported"
                )
            content = bytearray()
            async for chunk in response.aiter_bytes(chunk_size=16384):
                content.extend(chunk)
                if len(content) > MAX_RESPONSE_BYTES:
                    raise HTTPException(
                        502, "Public share response exceeds the import limit"
                    )
    try:
        html = content.decode("utf-8")
        try:
            return extract_conversation(html)
        except HTTPException as error:
            if error.status_code != 422:
                raise
        # Current public-share pages keep the conversation in a read-only,
        # unauthenticated share JSON resource rather than server-rendered HTML.
        # This is still the same validated host/share ID; no generic URL is used.
        api_url = f"https://{authority}/backend-api/share/{url.rsplit('/', 1)[-1]}"
        async with httpx.AsyncClient(
            trust_env=False,
            verify=True,
            follow_redirects=False,
            timeout=httpx.Timeout(5.0),
        ) as client:
            response = await client.get(
                api_url,
                headers={
                    "Host": HOST,
                    "Accept": "application/json",
                    "User-Agent": "AgentShield public-share importer/0.1",
                },
                extensions={"sni_hostname": HOST},
            )
            if response.status_code in {401, 403, 429}:
                raise HTTPException(
                    502,
                    "ChatGPT protected this public share from server retrieval. "
                    "Paste the visible conversation text instead.",
                )
            if response.status_code != 200:
                raise unsupported()
            if len(response.content) > MAX_RESPONSE_BYTES:
                raise HTTPException(
                    502, "Public share response exceeds the import limit"
                )
            try:
                payload = response.json()
                messages = _json_messages(payload)
                if not messages:
                    raise ValueError("no messages")
                text = "\n\n".join(f"{role}: {value}" for role, value in messages)
                if {role for role, _ in messages} != {"user", "assistant"}:
                    raise ValueError("incomplete conversation")
                return text
            except (ValueError, TypeError, RecursionError):
                raise unsupported() from None
    except UnicodeError:
        raise unsupported() from None


async def import_share(url: str) -> str:
    try:
        validate_share_url(url)
    except ValueError:
        raise HTTPException(422, "Invalid public ChatGPT share URL") from None
    try:
        return await asyncio.wait_for(_fetch(url), timeout=TOTAL_TIMEOUT)
    except HTTPException:
        raise
    except (asyncio.TimeoutError, httpx.TimeoutException):
        raise HTTPException(503, "Public share retrieval timed out") from None
    except (httpx.HTTPError, OSError):
        raise HTTPException(502, "Public share could not be retrieved safely") from None

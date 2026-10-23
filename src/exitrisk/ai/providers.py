"""Model providers for the optional AI review: one `complete(system, user)` call per provider.

Four providers are supported out of the box:

* **bedrock** - Amazon Bedrock in your own AWS account (the data stays in your account), signed with
  an AWS profile, or with a Bedrock API key;
* **anthropic** - the Claude API, which is also how a Claude Enterprise organisation calls Claude
  (an API key from the Claude Console of that organisation);
* **together** - Together AI (OpenAI-compatible), for open-weight reasoning models such as GLM;
* **openrouter** - OpenRouter (OpenAI-compatible), one key for many vendors' models.

Plain HTTPS through urllib with the operating system's trust store (corporate TLS proxies work), so
the feature needs no vendor SDK. Keys live in ``$EXITRISK_DATA_DIR/ai.json`` (mode 0600) or in the
usual environment variables, and are never sent to the browser.
"""

from __future__ import annotations

import json
import os
import re
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field

import truststore

from .. import __version__
from ..config import settings
from ..logging_config import get_logger

log = get_logger("ai")

TIMEOUT = 900  # seconds: a high-reasoning pass over a large estate can take several minutes
RETRIES = 5


@dataclass(frozen=True)
class Provider:
    key: str
    label: str
    note: str
    key_env: str
    key_url: str
    recommended: tuple[tuple[str, str], ...]  # (model id, label), best first
    model_pattern: str  # models listed by the provider that are worth offering
    third_party: bool = True


PROVIDERS = {
    p.key: p
    for p in (
        Provider(
            "bedrock",
            "Amazon Bedrock",
            "Runs in your own AWS account: the summary does not leave AWS. Uses an AWS profile, or a Bedrock API key.",
            "AWS_BEARER_TOKEN_BEDROCK",
            "https://docs.aws.amazon.com/bedrock/latest/userguide/api-keys.html",
            (
                ("global.anthropic.claude-fable-5-1", "Claude Fable 5.1 (recommended)"),
                ("global.anthropic.claude-opus-5-5", "Claude Opus 5.5"),
            ),
            r"anthropic\.claude-(fable|opus)",
            third_party=False,
        ),
        Provider(
            "anthropic",
            "Claude Enterprise / Claude API",
            "Anthropic's API. For Claude Enterprise, create the key in your organisation's Claude Console.",
            "ANTHROPIC_API_KEY",
            "https://console.anthropic.com/settings/keys",
            (("claude-fable-5-1", "Claude Fable 5.1 (recommended)"), ("claude-opus-5-5", "Claude Opus 5.5")),
            r"^claude-(fable|opus)",
        ),
        Provider(
            "together",
            "Together AI",
            "Open-weight reasoning models. GLM is recommended: strong reasoning and a long context.",
            "TOGETHER_API_KEY",
            "https://api.together.ai/settings/api-keys",
            (("zai-org/GLM-5.3", "GLM 5.3 (recommended)"), ("deepseek-ai/DeepSeek-V4", "DeepSeek V4")),
            r"glm|deepseek|kimi|qwen3",
        ),
        Provider(
            "openrouter",
            "OpenRouter",
            "One key for many vendors' models, billed by OpenRouter.",
            "OPENROUTER_API_KEY",
            "https://openrouter.ai/settings/keys",
            (
                ("anthropic/claude-fable-5.1", "Claude Fable 5.1 (recommended)"),
                ("anthropic/claude-opus-5.5", "Claude Opus 5.5"),
                ("z-ai/glm-5.3", "GLM 5.3"),
            ),
            r"^(anthropic/claude-(fable|opus)|z-ai/glm-\d)",
        ),
    )
}
OPENAI_BASE = {"together": "https://api.together.xyz/v1", "openrouter": "https://openrouter.ai/api/v1"}


class AIError(Exception):
    """A provider call failed in a way the console can explain (bad key, unknown model, quota)."""


@dataclass
class AISettings:
    provider: str = "bedrock"
    model: str = ""
    region: str = "us-east-1"  # Bedrock
    profile: str = ""  # Bedrock: AWS profile; blank = the default credential chain
    mask_names: bool = True
    keys: dict = field(default_factory=dict)

    def model_id(self) -> str:
        return self.model or PROVIDERS[self.provider].recommended[0][0]

    def api_key(self) -> str:
        return self.keys.get(self.provider) or os.environ.get(PROVIDERS[self.provider].key_env, "")

    def public(self) -> dict:
        """What the browser may see: never a key, only whether one is set and its last characters."""
        keys = {}
        for k, p in PROVIDERS.items():
            v = self.keys.get(k) or os.environ.get(p.key_env, "")
            keys[k] = {"set": bool(v), "hint": f"...{v[-4:]}" if len(v) > 8 else "", "env": not self.keys.get(k)}
        return {
            "provider": self.provider,
            "model": self.model,
            "region": self.region,
            "profile": self.profile,
            "mask_names": self.mask_names,
            "keys": keys,
        }


def _settings_path():
    return settings.data_dir / "ai.json"


def load_settings() -> AISettings:
    try:
        raw = json.loads(_settings_path().read_text())
    except FileNotFoundError:
        return AISettings()
    except (OSError, ValueError):
        log.exception("could not read AI settings; using defaults")
        return AISettings()
    s = AISettings(**{k: v for k, v in raw.items() if k in AISettings.__dataclass_fields__})
    if s.provider not in PROVIDERS:
        s.provider = "bedrock"
    return s


def save_settings(s: AISettings) -> None:
    settings.ensure_dirs()
    path = _settings_path()
    tmp = path.with_suffix(".tmp")
    # Keys are secrets: create the file private before writing them.
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(s.__dict__, f, indent=2)
    os.replace(tmp, path)


def _ssl_context() -> ssl.SSLContext:
    """The OS trust store, so a corporate TLS-inspecting proxy's root works as it does in the browser."""
    return truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)


_CTX = None


def _http(method: str, url: str, headers: dict, body: dict | None = None, timeout: int = TIMEOUT) -> dict:
    global _CTX
    _CTX = _CTX or _ssl_context()
    data = json.dumps(body).encode() if body is not None else None
    hdrs = {"User-Agent": f"exitrisk/{__version__}", "Content-Type": "application/json", **headers}
    delay = 5.0
    for attempt in range(RETRIES):
        if not url.startswith("https://"):
            raise AIError(f"Refusing a non-HTTPS endpoint: {url}")
        req = urllib.request.Request(url, data=data, headers=hdrs, method=method)  # noqa: S310 - https only, above
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=_CTX) as r:  # noqa: S310
                return json.loads(r.read() or b"{}")
        except urllib.error.HTTPError as exc:
            text = exc.read().decode("utf-8", "replace")[:600]
            if exc.code in (429, 500, 502, 503, 504, 529) and attempt < RETRIES - 1:
                wait = float(exc.headers.get("retry-after") or delay)
                log.warning("AI provider HTTP %d, retrying in %.0f s", exc.code, wait)
                time.sleep(min(wait, 120))
                delay *= 2
                continue
            raise AIError(_explain(exc.code, text)) from exc
        except (urllib.error.URLError, TimeoutError, ConnectionError) as exc:
            if attempt < RETRIES - 1:
                log.warning("AI provider unreachable (%s), retrying", exc)
                time.sleep(delay)
                delay *= 2
                continue
            raise AIError(f"Could not reach the provider: {exc}") from exc
    raise AIError("The provider kept failing")  # pragma: no cover


def _explain(code: int, text: str) -> str:
    msg = text
    try:
        j = json.loads(text)
        err = j.get("error", j)
        msg = err.get("message", text) if isinstance(err, dict) else str(err)
    except ValueError:
        pass
    if code in (401, 403):
        return f"The key was refused ({code}): {msg}. Check the API key, and that it may use this model."
    if code == 404:
        return f"Model or endpoint not found: {msg}. Pick another model from the list."
    if code == 429:
        return f"Rate limit or quota reached: {msg}"
    return f"Provider error {code}: {msg}"


@dataclass
class Reply:
    text: str
    input_tokens: int = 0
    output_tokens: int = 0


class Client:
    """One provider, one model. `complete` asks for deep reasoning where the model offers it, and drops
    the reasoning option (once, then for the rest of the run) if the model refuses it."""

    def __init__(self, s: AISettings):
        if s.provider not in PROVIDERS:
            raise AIError(f"Unknown provider {s.provider!r}")
        self.s = s
        self.model = s.model_id()
        self.reasoning = True
        if s.provider != "bedrock" and not s.api_key():
            raise AIError(f"No API key for {PROVIDERS[s.provider].label}. Enter one in AI review settings.")

    def complete(self, system: str, user: str, max_tokens: int = 16000) -> Reply:
        try:
            return self._call(system, user, max_tokens)
        except AIError as exc:
            if self.reasoning and re.search(r"think|reason|budget|effort|unsupported|not support", str(exc), re.I):
                log.info("model %s refused the reasoning option; retrying without it", self.model)
                self.reasoning = False
                return self._call(system, user, max_tokens)
            raise

    def _call(self, system: str, user: str, max_tokens: int) -> Reply:
        p = self.s.provider
        if p == "anthropic":
            body = {
                "model": self.model,
                "max_tokens": max_tokens,
                "system": system,
                "messages": [{"role": "user", "content": user}],
            }
            if self.reasoning:
                body["thinking"] = {"type": "enabled", "budget_tokens": max_tokens // 2}
            j = _http(
                "POST",
                "https://api.anthropic.com/v1/messages",
                {"x-api-key": self.s.api_key(), "anthropic-version": "2023-06-01"},
                body,
            )
            text = "".join(b.get("text", "") for b in j.get("content", []) if b.get("type") == "text")
            u = j.get("usage", {})
            return Reply(text, u.get("input_tokens", 0), u.get("output_tokens", 0))
        if p == "bedrock":
            return self._bedrock(system, user, max_tokens)
        body = {
            "model": self.model,
            "max_tokens": max_tokens,
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
        }
        if self.reasoning:
            if p == "openrouter":
                body["reasoning"] = {"effort": "high"}
            else:
                body["reasoning_effort"] = "high"
        j = _http("POST", f"{OPENAI_BASE[p]}/chat/completions", {"Authorization": f"Bearer {self.s.api_key()}"}, body)
        choices = j.get("choices") or []
        if not choices:
            raise AIError(f"The provider returned no answer: {json.dumps(j)[:300]}")
        text = choices[0].get("message", {}).get("content") or ""
        u = j.get("usage", {})
        return Reply(text, u.get("prompt_tokens", 0), u.get("completion_tokens", 0))

    def _bedrock(self, system: str, user: str, max_tokens: int) -> Reply:
        body = {
            "system": [{"text": system}],
            "messages": [{"role": "user", "content": [{"text": user}]}],
            "inferenceConfig": {"maxTokens": max_tokens},
        }
        if self.reasoning:
            body["additionalModelRequestFields"] = {"thinking": {"type": "enabled", "budget_tokens": max_tokens // 2}}
        key = self.s.api_key()
        if key:  # Bedrock API key: plain bearer token on the runtime endpoint
            model = urllib.parse.quote(self.model, safe="")
            url = f"https://bedrock-runtime.{self.s.region}.amazonaws.com/model/{model}/converse"
            j = _http("POST", url, {"Authorization": f"Bearer {key}"}, body)
        else:
            j = _bedrock_sdk(self.s, self.model, body)
        parts = ((j.get("output") or {}).get("message") or {}).get("content") or []
        text = "".join(c.get("text", "") for c in parts if "text" in c)
        u = j.get("usage", {})
        return Reply(text, u.get("inputTokens", 0), u.get("outputTokens", 0))


def _bedrock_sdk(s: AISettings, model: str, body: dict) -> dict:
    from botocore.config import Config
    from botocore.exceptions import BotoCoreError, ClientError

    from ..aws_session import make_session

    cfg = Config(read_timeout=TIMEOUT, retries={"max_attempts": 8, "mode": "adaptive"})
    try:
        client = make_session(s.profile or None, s.region).client("bedrock-runtime", config=cfg)
        return client.converse(modelId=model, **body)
    except ClientError as exc:
        err = exc.response.get("Error", {})
        raise AIError(f"Bedrock: {err.get('Code')}: {err.get('Message')}") from exc
    except BotoCoreError as exc:
        raise AIError(f"Bedrock: {exc}") from exc


def list_models(s: AISettings) -> list[dict]:
    """The provider's models worth offering, recommended first; the recommended list if listing fails."""
    p = PROVIDERS[s.provider]
    rec = [{"id": m, "label": label, "recommended": i == 0} for i, (m, label) in enumerate(p.recommended)]
    try:
        ids = _listed(s)
    except Exception as exc:  # listing is a convenience: the user can still type a model id
        log.info("could not list %s models: %s", s.provider, exc)
        return rec
    known = {m["id"] for m in rec}
    found = sorted((m for m in ids if re.search(p.model_pattern, m, re.I) and m not in known), reverse=True)
    return rec + [{"id": m, "label": m, "recommended": False} for m in found[:40]]


def _listed(s: AISettings) -> list[str]:
    if s.provider == "bedrock":
        from ..aws_session import make_session

        client = make_session(s.profile or None, s.region).client("bedrock")
        return [
            x["inferenceProfileId"]
            for x in client.list_inference_profiles(maxResults=1000)["inferenceProfileSummaries"]
        ]
    if s.provider == "anthropic":
        j = _http(
            "GET",
            "https://api.anthropic.com/v1/models?limit=100",
            {"x-api-key": s.api_key(), "anthropic-version": "2023-06-01"},
            timeout=30,
        )
        return [m["id"] for m in j.get("data", [])]
    j = _http("GET", f"{OPENAI_BASE[s.provider]}/models", {"Authorization": f"Bearer {s.api_key()}"}, timeout=30)
    data = j if isinstance(j, list) else j.get("data", [])
    return [m["id"] for m in data]


def test_connection(s: AISettings) -> dict:
    """One tiny call, so a bad key or model fails in seconds, not twenty minutes into a review."""
    started = time.perf_counter()
    client = Client(s)
    client.reasoning = False
    reply = client.complete("Reply with the single word OK.", "Connection test.", max_tokens=16)
    return {
        "ok": True,
        "model": client.model,
        "reply": reply.text.strip()[:40],
        "seconds": round(time.perf_counter() - started, 1),
    }

"""Recall backends — the sensor behind the sterilizer's second pass.

pipeline.py needs one thing from a recall backend: a callable that takes
text and returns [(verbatim_span, TYPE), ...] with TYPE from
detect.PII_TYPES. Everything downstream (grounding, replacement, residual
loop) is the same whichever sensor produced the proposals, so swapping the
sensor never changes the safety story: a span that is not byte-for-byte in
the input is dropped, and the script does every mutation.

Two backends (docs/pii-sterilization.md, "Recall backends"):

  llm     the llama.cpp chat-completions path (llmclient.py) — a model
          server at LLM_URL, grammar-constrained. Best recall; needs a
          machine that can reach one.
  gliner  an in-process zero-shot NER model (GLiNER, Apache-2.0) run on
          CPU — the shape a member's laptop can carry. Optional import:
          if PII_RECALL=gliner and the package is absent the service
          refuses to START (fail closed at boot, not at first request).

Selection is by env (PII_RECALL), never by the caller: a request cannot
downgrade the sensor. Stdlib-only here; the gliner package is the one
optional third-party import in the module and it is loaded lazily.
"""

from typing import Callable, List, Tuple

from . import llmclient
from .detect import PII_TYPES
from .llmclient import RecallError  # noqa: F401  (re-exported: one except-clause for every backend)

Findings = List[Tuple[str, str]]


BACKENDS = ("llm", "gliner")

# GLiNER is zero-shot: the labels ARE the prompt. Plain-English phrases
# recall better than bare enum names; each maps back to the closed
# vocabulary the vault and the grammar use. "OTHER" is deliberately not a
# label — a catch-all label recalls everything and precision collapses.
GLINER_LABELS = {
    "person name": "PERSON",
    "email address": "EMAIL",
    "phone number": "PHONE",
    "street address": "ADDRESS",
    "social security number": "SSN",
    "date of birth": "DOB",
    "credit card number": "CREDIT_CARD",
    "bank account number": "BANK_ACCOUNT",
    "ip address": "IP_ADDRESS",
    "mac address": "MAC_ADDRESS",
    "username": "USERNAME",
    "password or api key or secret": "CREDENTIAL",
    "medical condition or diagnosis": "MEDICAL",
    "id number or passport or license number": "ID_NUMBER",
    "employer or school or organization": "ORG",
    "specific location that identifies a person": "LOCATION",
}
assert set(GLINER_LABELS.values()) <= set(PII_TYPES)

DEFAULT_GLINER_MODEL = "urchade/gliner_multi_pii-v1"
DEFAULT_GLINER_THRESHOLD = 0.5
DEFAULT_GLINER_VERIFY_THRESHOLD = 0.3


class LlmBackend:
    name = "llm"

    def __init__(self, llm_url, timeout):
        self.llm_url = llm_url
        self.timeout = timeout

    def extract(self, text):  # type: (str) -> Findings
        return llmclient.extract(text, llm_url=self.llm_url, timeout=self.timeout)

    def verify(self, text):  # type: (str) -> Findings
        return llmclient.verify(text, llm_url=self.llm_url, timeout=self.timeout)

    def describe(self):
        return "llm=%s" % self.llm_url


class GlinerBackend:
    """In-process GLiNER. The model object is created once at boot (that is
    the fail-closed moment) and shared; predict_entities is called per
    request with the label list above."""

    name = "gliner"

    def __init__(self, model_name, threshold, verify_threshold, loader=None):
        self.model_name = model_name
        self.threshold = float(threshold)
        self.verify_threshold = float(verify_threshold)
        load = loader or _load_gliner
        try:
            self.model = load(model_name)
        except ImportError as e:
            raise RecallError(
                "PII_RECALL=gliner but the 'gliner' package is not installed "
                "(pip install gliner); refusing to start without a recall pass"
            ) from e
        except Exception as e:  # model download / load failure
            raise RecallError("gliner model %r failed to load: %s" % (model_name, e)) from e

    def _predict(self, text, threshold):  # type: (str, float) -> Findings
        try:
            ents = self.model.predict_entities(
                text, list(GLINER_LABELS), threshold=threshold)
        except Exception as e:
            raise RecallError("gliner prediction failed: %s" % e) from e
        out = []
        seen = set()
        for ent in ents:
            try:
                span, label = ent["text"], ent["label"]
            except (KeyError, TypeError):
                continue
            typ = GLINER_LABELS.get(label)
            if typ is None or not isinstance(span, str):
                continue
            key = (span, typ)
            if key in seen:
                continue
            seen.add(key)
            out.append(key)
        return out

    def extract(self, text):
        return self._predict(text, self.threshold)

    def verify(self, text):
        return self._predict(text, self.verify_threshold)

    def describe(self):
        return "gliner=%s@%.2f" % (self.model_name, self.threshold)


def _load_gliner(model_name):
    from gliner import GLiNER  # optional dependency, imported here only
    return GLiNER.from_pretrained(model_name)


def build_backend(env, loader=None):
    """Select and construct the recall backend from the environment.
    Raises RecallError (fail closed) on an unknown backend or a backend
    that cannot start."""
    kind = env.get("PII_RECALL", "llm").strip().lower()
    if kind == "llm":
        return LlmBackend(env.get("LLM_URL", "http://llm:8080"),
                          float(env.get("PII_LLM_TIMEOUT", "300")))
    if kind == "gliner":
        return GlinerBackend(
            env.get("GLINER_MODEL", DEFAULT_GLINER_MODEL),
            env.get("GLINER_THRESHOLD", DEFAULT_GLINER_THRESHOLD),
            env.get("GLINER_VERIFY_THRESHOLD", DEFAULT_GLINER_VERIFY_THRESHOLD),
            loader=loader,
        )
    raise RecallError("PII_RECALL=%r is not one of %s" % (kind, BACKENDS))

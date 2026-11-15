"""Tool-use loop over the Anthropic Messages API (manual loop).

Hard limits: MAX_TOOL_CALLS executed tools and MAX_SECONDS wall clock per
run. FINAL_RESERVE_S of the budget is kept for the closing request, in which
the model is told to answer with final_diagnosis now. Some current models
reject a forced tool_choice with a 400, so the closing request forces only
where the model allows it and otherwise steers via the prompt. No
final_diagnosis -> RuntimeError (the caller falls back to Ollama).
"""

import asyncio
import time
from collections.abc import Callable

import anthropic

from .facts import DIAGNOSIS_SCHEMA, Diagnosis, diagnosis_from

MAX_TOOL_CALLS = 15
MAX_SECONDS = 180.0
FINAL_RESERVE_S = 45.0
MAX_TOKENS = 4096
FINAL_TOOL = "final_diagnosis"

SYSTEM_PROMPT = """\
You are the investigator of LANOT, a monitoring system for a small local network.
{network}

Your role:
- You only investigate. You may only read and examine. You do not fix anything, \
restart anything or change any setting.
- Never claim that you changed, fixed or restarted something. Your tools cannot do that.
- Keep facts (backed by logs, metrics, tests) clearly apart from assumptions. Never present an \
assumption as a fact.
- Set the confidence honestly: "certain" only when the evidence shows the cause beyond doubt; \
"likely" when most of it points that way; otherwise "unclear".
- Suggestions are only things the user could check, never commands that change anything.
- Write in plain English that a non-expert can follow.

You get a fact bundle about the incident. Use the tools deliberately and sparingly (at most \
15 calls). Always finish the investigation by calling the tool final_diagnosis.\
"""

FINAL_PROMPT = ("The limit for tools or time is reached. Call final_diagnosis right now, "
                "using only what you know so far. No more tools.")

FINAL_TOOL_DEF = {
    "name": FINAL_TOOL,
    "description": "Finishes the investigation and returns the diagnosis. Must be called exactly once "
                   "at the end.",
    "input_schema": DIAGNOSIS_SCHEMA,
    "strict": True,
}

# Models that answer 400 to tool_choice {"type": "tool"}.
_NO_FORCED_TOOL_CHOICE = ("claude-opus-5-5", "claude-sonnet-5-5", "claude-fable-5-2")


def describe_network(cfg) -> str:
    """One line per configured device, for the system prompt."""
    lines = ["The network:"]
    if cfg is None or not cfg.hosts:
        lines.append("- (no hosts configured)")
    else:
        for h in cfg.hosts:
            mon = ", runs LANOT itself" if h.id == cfg.monitor_host else ""
            batt = ", has a battery" if h.has_battery else ""
            lines.append(f"- {h.display_name} (id {h.id}, {h.role}, {h.address}{mon}{batt})")
    if cfg is not None:
        lines.append(f"- router: {cfg.router.display_name} ({cfg.router.host})")
    return "\n".join(lines)


def system_prompt(cfg) -> str:
    return SYSTEM_PROMPT.replace("{network}", describe_network(cfg))


def _supports_forced_choice(model: str) -> bool:
    return not model.startswith(_NO_FORCED_TOOL_CHOICE)


def _final_input(resp) -> dict | None:
    for b in resp.content:
        if getattr(b, "type", None) == "tool_use" and b.name == FINAL_TOOL:
            return b.input
    return None


async def run_anthropic(bundle, tools, settings, *, client=None, bundle_text: str | None = None,
                        monotonic: Callable[[], float] = time.monotonic) -> Diagnosis:
    """`tools` is a Toolbox. `bundle_text` overrides bundle.to_text() (already redacted)."""
    if client is None:
        client = anthropic.AsyncAnthropic(api_key=settings.anthropic_api_key)
    model = settings.anthropic_model
    system = system_prompt(settings.config)
    started = monotonic()
    deadline = started + MAX_SECONDS
    loop_deadline = deadline - FINAL_RESERVE_S
    text = bundle_text if bundle_text is not None else bundle.to_text()
    all_tools = [*tools.definitions, FINAL_TOOL_DEF]
    messages: list[dict] = [{"role": "user", "content": [{
        "type": "text",
        "text": "New incident. Here is the automatically collected fact bundle (JSON):\n\n" + text
                + "\n\nFind the cause and finish with final_diagnosis."}]}]
    calls = 0

    def result(data: dict) -> Diagnosis:
        return diagnosis_from(data, model, calls, monotonic() - started)

    async def create(timeout: float, **extra):
        return await asyncio.wait_for(
            client.messages.create(model=model, max_tokens=MAX_TOKENS, system=system,
                                   tools=all_tools, messages=messages, **extra),
            max(timeout, 0.01))

    while calls < MAX_TOOL_CALLS and monotonic() < loop_deadline:
        try:
            resp = await create(loop_deadline - monotonic())
        except TimeoutError:
            break
        if resp.stop_reason == "refusal":
            raise RuntimeError("the model refused the request")
        final = _final_input(resp)
        if final is not None:
            return result(final)
        messages.append({"role": "assistant", "content": resp.content})
        uses = [b for b in resp.content if getattr(b, "type", None) == "tool_use"]
        if not uses:
            if resp.stop_reason == "pause_turn":
                continue
            break  # answered without final_diagnosis: ask once more below
        results = []
        for u in uses:
            remaining = loop_deadline - monotonic()
            if calls >= MAX_TOOL_CALLS or remaining <= 0:
                results.append({"type": "tool_result", "tool_use_id": u.id, "is_error": True,
                                "content": "Not run: the limit for tools or time is reached."})
                continue
            calls += 1
            try:
                out = await asyncio.wait_for(tools.call(u.name, u.input), remaining)
            except TimeoutError:
                out = "the tool timed out"
            results.append({"type": "tool_result", "tool_use_id": u.id, "content": out})
        messages.append({"role": "user", "content": results})

    # closing request: final_diagnosis now
    nudge = {"type": "text", "text": FINAL_PROMPT}
    if messages[-1]["role"] == "user":
        messages[-1] = {"role": "user", "content": [*messages[-1]["content"], nudge]}
    else:
        messages.append({"role": "user", "content": [nudge]})
    extra = {"tool_choice": {"type": "tool", "name": FINAL_TOOL}} if _supports_forced_choice(model) else {}
    resp = await create(max(deadline - monotonic(), 1.0), **extra)
    final = _final_input(resp)
    if final is None:
        raise RuntimeError("the model ended without final_diagnosis")
    return result(final)

"""Investigator: facts -> Anthropic API (online) -> Ollama -> "none". Never
raises for model failures; the fact bundle is stored in every case."""

import asyncio
import datetime as dt
import json
import logging
import time
from collections.abc import Callable
from dataclasses import asdict
from zoneinfo import ZoneInfo

from ..db import Incident
from . import anthropic_run
from .anthropic_run import run_anthropic
from .facts import Deps, Diagnosis, FactBundle, collect_facts
from .ollama_run import OLLAMA_TIMEOUT_S, run_ollama
from .tools import Toolbox

log = logging.getLogger(__name__)

DAILY_CAP = 20
NONE_SUMMARY = "No AI assessment available. See the dashboard for the facts."
CAP_SUMMARY = "Daily limit for AI investigations reached. See the dashboard for the facts."


def _no_ai(summary: str, duration_s: float) -> Diagnosis:
    return Diagnosis(summary=summary, what_happened="", cause="", confidence="unclear", suggestions=[],
                     evidence=[], model="none", tool_calls=0, duration_s=round(duration_s, 2))


class Investigator:
    def __init__(self, deps: Deps, settings, clock: Callable[[], float], *, notifier=None):
        self.deps, self.settings, self.clock, self.notifier = deps, settings, clock, notifier
        if deps.config is None:
            deps.config = settings.config
        self.tools = Toolbox(deps, settings, clock)

    def _quota_key(self) -> str:
        day = dt.datetime.fromtimestamp(self.clock(), ZoneInfo(self.settings.tz)).date()
        return f"investigations_{day.isoformat()}"

    async def _internet_down(self) -> bool:
        return any(i.rule == "internet_down" for i in await asyncio.to_thread(self.deps.db.open_incidents))

    async def _has_ai_diagnosis(self, incident_id: int) -> bool:
        fresh = await asyncio.to_thread(self.deps.db.get_incident, incident_id)
        try:
            prev = json.loads(fresh.diagnosis_json) if fresh and fresh.diagnosis_json else None
        except ValueError:
            return False
        return isinstance(prev, dict) and str(prev.get("model") or "none") != "none"

    async def _diagnose(self, facts: FactBundle) -> Diagnosis | None:
        if self.settings.anthropic_api_key and not await self._internet_down():
            try:
                # backstop only: run_anthropic enforces MAX_SECONDS itself
                return await asyncio.wait_for(
                    run_anthropic(facts, self.tools, self.settings, client=self.deps.anthropic),
                    anthropic_run.MAX_SECONDS + 15)
            except Exception as e:  # incl. timeouts, API and connection errors
                log.warning("Anthropic API investigation failed (%s), falling back to Ollama", type(e).__name__)
        try:
            return await asyncio.wait_for(run_ollama(facts, self.settings, post=self.deps.ollama_post),
                                          OLLAMA_TIMEOUT_S + 5)
        except Exception as e:
            log.warning("Ollama investigation failed: %s", type(e).__name__)
        return None

    async def investigate(self, incident: Incident, *, followup: bool = False) -> Diagnosis:
        """`followup`: a second look at a long-running incident. It is stored with
        "followup": true, and it never replaces an AI diagnosis with a no-AI
        fallback (then nothing is stored and nothing is pushed)."""
        started = time.monotonic()
        facts = await collect_facts(incident, self.deps)
        db = self.deps.db
        if await asyncio.to_thread(db.take_quota, self._quota_key(), DAILY_CAP):
            d = await self._diagnose(facts) or _no_ai(NONE_SUMMARY, time.monotonic() - started)
        else:
            d = _no_ai(CAP_SUMMARY, time.monotonic() - started)
        if followup and d.model == "none" and await self._has_ai_diagnosis(incident.id):
            log.info("follow-up for incident %s gave no AI result; keeping the previous diagnosis", incident.id)
            return d
        extra = {"followup": True} if followup else {}
        stored = json.dumps({**asdict(d), **extra, "facts": facts.to_dict()}, ensure_ascii=False)
        await asyncio.to_thread(db.set_diagnosis, incident.id, stored)
        if self.notifier is not None:
            fresh = await asyncio.to_thread(db.get_incident, incident.id)
            try:
                await self.notifier.on_diagnosis(fresh or incident)
            except Exception:
                log.exception("diagnosis push failed for incident %s", incident.id)
        return d

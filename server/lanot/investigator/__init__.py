"""Investigator: gathers fixed facts for a new incident, then asks a model
(the Anthropic API with read-only tools, or a local Ollama model without tools)
to explain it. It never changes anything."""

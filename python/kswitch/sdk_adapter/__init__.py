"""KS-EP-098a SDK callback watcher adapters."""

from .openai_agents import CallbackRegistrationEvent, patch_callback_registrar

__all__ = ["CallbackRegistrationEvent", "patch_callback_registrar"]

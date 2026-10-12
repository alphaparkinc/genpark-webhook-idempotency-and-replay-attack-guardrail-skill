"""Webhook Idempotency & Replay Attack Guardrail.
100% Python Standard Library.
"""

class WebhookIdempotencyGuardrail:
    """Verifies webhook timestamp freshness, deduplicates event delivery IDs, and prevents replay attacks."""

    @staticmethod
    def verify_delivery(event_id: str, timestamp_sec: int, current_time_sec: int, seen_ids: list, tolerance_sec: int = 300) -> dict:
        age = abs(current_time_sec - timestamp_sec)
        is_duplicate = event_id in seen_ids
        is_stale = age > tolerance_sec

        if is_duplicate:
            status = "REJECTED_DUPLICATE_EVENT"
            accepted = False
        elif is_stale:
            status = "REJECTED_REPLAY_WINDOW_EXPIRED"
            accepted = False
        else:
            status = "ACCEPTED_FRESH_DELIVERY"
            accepted = True

        return {
            "event_id": event_id,
            "accepted": accepted,
            "status": status,
            "timestamp_drift_sec": age
        }

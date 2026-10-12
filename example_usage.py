"""Example usage for Webhook Idempotency & Replay Attack Guardrail."""
from client import WebhookIdempotencyGuardrail

if __name__ == "__main__":
    res = WebhookIdempotencyGuardrail.verify_delivery("evt_991", 1700000000, 1700000120, ["evt_100"])
    print("Status:", res["status"])

"""MCP server for Webhook Idempotency & Replay Attack Guardrail."""
import sys
import json
from client import WebhookIdempotencyGuardrail

def handle_request(req):
    method = req.get("method")
    if method == "tools/list":
        return {
            "tools": [{
                "name": "verify_webhook_idempotency",
                "description": "Checks webhook delivery freshness and deduplicates event IDs against replay attacks",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "event_id": {"type": "string"},
                        "timestamp_sec": {"type": "integer"},
                        "current_time_sec": {"type": "integer"},
                        "seen_ids": {"type": "array"},
                        "tolerance_sec": {"type": "integer"}
                    },
                    "required": ["event_id", "timestamp_sec", "current_time_sec", "seen_ids"]
                }
            }]
        }
    elif method == "tools/call":
        params = req.get("params", {})
        if params.get("name") == "verify_webhook_idempotency":
            args = params.get("arguments", {})
            res = WebhookIdempotencyGuardrail.verify_delivery(
                args.get("event_id", ""),
                int(args.get("timestamp_sec", 0)),
                int(args.get("current_time_sec", 0)),
                args.get("seen_ids", []),
                int(args.get("tolerance_sec", 300))
            )
            return {"content": [{"type": "text", "text": json.dumps(res, indent=2)}]}
    return {"error": "Method not found"}

if __name__ == "__main__":
    for line in sys.stdin:
        if line.strip():
            print(json.dumps(handle_request(json.loads(line))))
            sys.stdout.flush()

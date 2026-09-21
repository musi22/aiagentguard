"""Real Stripe refund loop. Requires LangGraph/LangChain and configured AgentGuard + Stripe secrets."""
from __future__ import annotations

import os

from agentguard import AgentGuard, AuthorizationDenied
from langchain_core.tools import tool

guard = AgentGuard(
    api_key=os.environ["AGENTGUARD_API_KEY"],
    base_url=os.getenv("AGENTGUARD_GATEWAY_URL", "http://localhost:8001"),
    approval_timeout=900,
)


@tool
def refund_customer(payment_intent: str, amount: float) -> dict:
    """Refund a Stripe PaymentIntent after AgentGuard authorizes the exact arguments."""
    return guard.execute(
        "stripe.refund", {"payment_intent": payment_intent, "amount": amount},
        context={"environment": os.getenv("AGENT_ENVIRONMENT", "development")},
        idempotency_key=f"refund-{payment_intent}-{amount:.2f}",
    )


if __name__ == "__main__":
    try:
        print(refund_customer.invoke({
            "payment_intent": os.environ["STRIPE_PAYMENT_INTENT"],
            "amount": float(os.getenv("REFUND_AMOUNT", "50")),
        }))
    except AuthorizationDenied as exc:
        print(f"Denied by AgentGuard: {exc}")

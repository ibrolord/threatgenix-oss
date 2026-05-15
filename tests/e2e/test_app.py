"""Test ASGI app that patches Bedrock before importing the real app."""
import os
import sys

# Ensure backend is on path
backend_dir = os.path.join(os.path.dirname(__file__), "..", "..", "threatgenix", "backend")
sys.path.insert(0, backend_dir)

# Patch BedrockClient before importing the app
FAKE_BEDROCK_EXTRACTION = {
    "components": [
        {"name": "Mobile App", "component_type": "external_entity", "confidence": 0.95,
         "description": "iOS/Android customer-facing banking interface"},
        {"name": "API Gateway", "component_type": "process", "confidence": 0.95,
         "description": "Routes requests, rate limiting, authentication"},
        {"name": "Authentication Service", "component_type": "process", "confidence": 0.95,
         "description": "OAuth2/OIDC, MFA, session management"},
        {"name": "Account Service", "component_type": "process", "confidence": 0.95,
         "description": "Balance inquiries, account details, statements"},
        {"name": "Payment Service", "component_type": "process", "confidence": 0.95,
         "description": "e-Transfer, bill payments, internal transfers"},
        {"name": "Database", "component_type": "data_store", "confidence": 0.95,
         "description": "PostgreSQL, stores account data, transaction history"},
        {"name": "Message Queue", "component_type": "data_store", "confidence": 0.9,
         "description": "Async processing for payments and notifications"},
        {"name": "Notification Service", "component_type": "process", "confidence": 0.9,
         "description": "Push notifications, email, SMS alerts"},
    ],
    "flows": [
        {"source": "Mobile App", "target": "API Gateway", "label": "HTTPS API calls (REST)", "confidence": 0.95},
        {"source": "API Gateway", "target": "Authentication Service", "label": "token validation", "confidence": 0.95},
        {"source": "API Gateway", "target": "Account Service", "label": "account queries", "confidence": 0.95},
        {"source": "API Gateway", "target": "Payment Service", "label": "payment requests", "confidence": 0.95},
        {"source": "Account Service", "target": "Database", "label": "read account data", "confidence": 0.95},
        {"source": "Payment Service", "target": "Database", "label": "write transaction records", "confidence": 0.95},
        {"source": "Payment Service", "target": "Message Queue", "label": "async payment events", "confidence": 0.9},
        {"source": "Message Queue", "target": "Notification Service", "label": "payment confirmations", "confidence": 0.9},
    ],
    "boundaries": [
        {"name": "Internet Boundary", "contains": ["Mobile App", "API Gateway"]},
        {"name": "Internal Boundary", "contains": ["API Gateway", "Authentication Service", "Account Service", "Payment Service"]},
        {"name": "Data Boundary", "contains": ["Database", "Message Queue"]},
    ],
}

class FakeBedrockClient:
    """Fake BedrockClient that returns canned responses."""

    def __init__(self, *args, **kwargs):
        self.provider_name = "bedrock"
        self.model_id = "fake-bedrock-model"
        self.model_name = self.model_id

    def call_with_tools(self, system_message, user_message, tools, **kwargs):
        return FAKE_BEDROCK_EXTRACTION


# Import and patch the current LLM provider module before importing the app.
from app.services import llm_client as llm_module  # noqa: E402

llm_module.BedrockProvider = FakeBedrockClient
llm_module.PROVIDER_REGISTRY = [
    (name, FakeBedrockClient if name == "bedrock" else provider)
    for name, provider in llm_module.PROVIDER_REGISTRY
]
llm_module._PROVIDER_MAP = {
    name: provider for name, provider in llm_module.PROVIDER_REGISTRY
}

# Now import the real app (which will use our patched BedrockClient)
from app.main import app  # noqa: E402

__all__ = ["app"]

"""Test ASGI app that patches Bedrock before importing the real app."""
import os
import sys
from unittest.mock import MagicMock

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

# Import and patch the bedrock client module
from app.services import bedrock_client as bc_module

_OriginalBedrockClient = bc_module.BedrockClient


class FakeBedrockClient:
    """Fake BedrockClient that returns canned responses."""

    def __init__(self, *args, **kwargs):
        pass

    def call_with_tools(self, system_message, user_message, tools, **kwargs):
        return FAKE_BEDROCK_EXTRACTION


# Monkey-patch at module level
bc_module.BedrockClient = FakeBedrockClient

# Now import the real app (which will use our patched BedrockClient)
from app.main import app  # noqa: E402

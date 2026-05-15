import jwt


def decode_partner_token_without_verification(token: str) -> dict:
    return jwt.decode(token, options={"verify_signature": False})

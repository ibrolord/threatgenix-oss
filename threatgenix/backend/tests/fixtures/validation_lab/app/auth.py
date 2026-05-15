import jwt


def decode_partner_token(token: str) -> dict:
    return jwt.decode(token, options={"verify_signature": False})

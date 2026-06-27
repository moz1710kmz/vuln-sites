"""
VulnBoard 用の JWT ユーティリティ（標準ライブラリのみ）。

意図的に脆弱な JWT 実装。実運用では絶対に使わないこと（隔離環境専用）。
PyJWT 等の安全なライブラリは alg=none や弱い検証を仕様で拒否するため、
脆弱性を正確に再現する目的で hmac/hashlib/base64/json で自前実装している。

仕込んでいる脆弱性（vulndata の JWT-1〜6 に対応）:
- JWT-1: alg=none を受理（無署名トークンを信頼）
- JWT-2: 署名を検証しないデコード経路（decode_unverified）
- JWT-3: HS256 を弱い固定秘密鍵で署名（オフライン総当りで偽造可能）
- JWT-4: ペイロードに機微情報（パスワード等）を平文で格納（呼び出し側で実施）
- JWT-5: exp を発行せず、検証時にも有効期限を確認しない
- JWT-6: alg 混同（RS256 を想定した公開鍵 PEM を HS256 の HMAC 鍵として受理）
"""

import base64
import hashlib
import hmac
import json

# JWT-3: 弱い固定の HMAC 秘密鍵（既存 AUTH-2 の secret_key と同テーマ）
HS_SECRET = "secret123"

# JWT-6: RS256 用の公開鍵 PEM。公開情報なので攻撃者も入手でき（/api/pubkey で配布）、
# これを HMAC 秘密鍵として HS256 署名するとサーバが受理してしまう（alg 混同）。
RSA_PUBLIC_PEM = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwWye/SDQzg4wPHIMYJ9U
toZdPctyzYRdTag03n5FZMUYYN3YenXHIzERSmjYsHJCgSTmQnwA3ckHWO1P09yA
YGg6pCzWeLDo2asBnRYaBMQVO7HtZ+H6aBfrG6bd3l8tZ2E/UeEXOrUK1VFh6goD
ZKXCXVAbQS3LTaAgKFGa8Ft5Ic5eFxu8+y8vtw4fG6eo90p/SjA7xT+opjR0w8rS
WCLgxb6GdGchF5I4mdrlOwdrBT0LqU2kC+9Z0b3xT2KVlD4wwR2EjbrWY2zxCrhp
/L+sutXRRTYBJIL/yiFvtmIKZYyKY8jjl4ddFk3nJvITjQkAgtMvv/28nFN11PDQ
2wIDAQAB
-----END PUBLIC KEY-----
"""


def b64url_encode(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def b64url_decode(seg):
    pad = "=" * (-len(seg) % 4)
    return base64.urlsafe_b64decode(seg + pad)


def _segment(obj):
    return b64url_encode(json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode())


def _hs256(signing_input, secret):
    key = secret.encode() if isinstance(secret, str) else secret
    return b64url_encode(hmac.new(key, signing_input, hashlib.sha256).digest())


def encode(payload, alg="HS256", secret=HS_SECRET):
    """JWT を生成する。alg='none'（無署名）や任意の secret での署名も可能（攻撃の再現用）。"""
    header = {"alg": alg, "typ": "JWT"}
    signing_input = (_segment(header) + "." + _segment(payload)).encode()
    if alg == "none":
        sig = ""
    elif alg == "HS256":
        sig = _hs256(signing_input, secret)
    else:
        raise ValueError("unsupported alg for encode: %s" % alg)
    return signing_input.decode() + "." + sig


def decode_unverified(token):
    """JWT-2: 署名を一切検証せずにクレームを読む（危険）。失敗時は None。"""
    try:
        payload_b64 = token.split(".")[1]
        return json.loads(b64url_decode(payload_b64))
    except Exception:
        return None


def verify(token):
    """
    意図的に壊した検証関数。次のいずれかを満たせば「正当」とみなしクレームを返す:
      - alg=none            → 署名なしで受理（JWT-1）
      - HS256 + 弱い秘密鍵    → 受理（JWT-3）
      - HS256 + 公開鍵 PEM    → 受理（JWT-6 alg 混同）
    exp は一切確認しない（JWT-5）。不正な場合は None を返す。
    """
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        header_b64, payload_b64, sig = parts
        header = json.loads(b64url_decode(header_b64))
        payload = json.loads(b64url_decode(payload_b64))
        alg = (header.get("alg") or "").lower()
        signing_input = (header_b64 + "." + payload_b64).encode()
        if alg == "none":
            return payload                                   # JWT-1
        if alg == "hs256":
            for key in (HS_SECRET, RSA_PUBLIC_PEM):          # JWT-3 / JWT-6
                if hmac.compare_digest(sig, _hs256(signing_input, key)):
                    return payload
        return None
    except Exception:
        return None

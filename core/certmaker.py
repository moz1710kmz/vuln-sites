"""
評価用の自己署名証明書を「1枚だけ」作って各アプリで共有する（HTTPS 化のため）。

このサイト群はローカル/隔離環境専用で本番公開しない。HTTPS 化の狙いは
セキュリティではなく「評価の現実性」（実際のスキャナ評価対象はほぼ HTTPS で、
Secure Cookie / HSTS / TLS 設定不備など HTTPS でしか存在しない指摘を題材にできる）。
そのため自己署名で十分で、各ツールは証明書検証をスキップして使う。

- 出力: certs/vuln.crt（証明書）, certs/vuln.key（秘密鍵）
- SAN: DNS:localhost, IP:127.0.0.1（ブラウザ/クライアントの名前一致用）
- 冪等: 既にあれば再生成しない（= VulnBank/VulnEC/VulnBoard/コンパネで同じ1枚を共有）
- 既定 HTTPS。VULN_TLS=0 のときだけ HTTP に落とす（ssl_context_from_env が None を返す）

単体実行: `python certmaker.py` で certs/ に証明書を生成する。
"""

import datetime
import ipaddress
import os

# このモジュールは core/ 配下にあるが、証明書はリポジトリ直下（core の親）の certs/ に置く
# （VulnBank/VulnEC/VulnBoard/コンパネで同じ1枚を共有するため）。
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CERT_DIR = os.path.join(BASE_DIR, "certs")
CERT_PATH = os.path.join(CERT_DIR, "vuln.crt")
KEY_PATH = os.path.join(CERT_DIR, "vuln.key")

_FALSEY = ("0", "false", "no", "off", "")


def tls_enabled(environ=None):
    """VULN_TLS を見て HTTPS を使うか判定する（未指定なら既定 OFF＝HTTP）。"""
    environ = os.environ if environ is None else environ
    return environ.get("VULN_TLS", "0").strip().lower() not in _FALSEY


def cert_paths(environ=None):
    """使用する (証明書, 秘密鍵) のパス。TLS_CERT/TLS_KEY で持ち込みも可能。"""
    environ = os.environ if environ is None else environ
    cert = environ.get("TLS_CERT") or CERT_PATH
    key = environ.get("TLS_KEY") or KEY_PATH
    return cert, key


def ensure_cert(cert_path=None, key_path=None):
    """証明書が無ければ生成し、(cert_path, key_path) を返す（冪等）。"""
    cert_path = cert_path or CERT_PATH
    key_path = key_path or KEY_PATH
    if os.path.exists(cert_path) and os.path.exists(key_path):
        return cert_path, key_path
    return generate(cert_path, key_path)


def generate(cert_path=None, key_path=None):
    """自己署名証明書を新規生成して書き出す（既存があっても上書き）。"""
    cert_path = cert_path or CERT_PATH
    key_path = key_path or KEY_PATH
    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
    except ImportError as e:  # pragma: no cover - 依存未導入時の案内
        raise RuntimeError(
            "HTTPS 化には cryptography が必要です。`pip install -r requirements.txt` を実行するか、"
            "HTTP で動かす場合は VULN_TLS=0 を設定してください。"
        ) from e

    os.makedirs(os.path.dirname(os.path.abspath(cert_path)), exist_ok=True)

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "VulnSite (eval only, do not trust)"),
    ])
    san = x509.SubjectAlternativeName([
        x509.DNSName("localhost"),
        x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
    ])
    now = datetime.datetime.utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=3650))  # 評価用に長め(約10年)
        .add_extension(san, critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        # Apple/Chrome は TLS サーバ証明書に serverAuth EKU を要求する。
        # これが無いと、ユーザーが信頼登録しても macOS で TLS 用に信頼されないことがある。
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .sign(key, hashes.SHA256())
    )

    # 秘密鍵は 0600 で先に書く
    with open(key_path, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))
    try:
        os.chmod(key_path, 0o600)
    except OSError:  # pragma: no cover - 一部FSで chmod 不可
        pass
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    return cert_path, key_path


def ssl_context_from_env(environ=None):
    """
    werkzeug/Flask の run に渡す ssl_context を返す。
    HTTPS なら (cert, key) のタプル（無ければ生成）、HTTP なら None。
    """
    environ = os.environ if environ is None else environ
    if not tls_enabled(environ):
        return None
    cert, key = cert_paths(environ)
    return ensure_cert(cert, key)


if __name__ == "__main__":
    c, k = ensure_cert()
    print("証明書:", c)
    print("秘密鍵:", k)

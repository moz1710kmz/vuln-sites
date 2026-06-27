"""
VulnEC 用の「外部住所検索 API」役のスタンドアロンサーバ。

VulnEC 本体（別コンテナ）とは独立して動き、購入フローの配送先入力で
「住所検索」ボタンから *ブラウザが直接* 叩く想定の外部サービスを模倣する。
郵便番号 -> 都道府県/市区町村/町域 を返すだけの小さな静的データを持つ。

依存を増やさないため Python 標準ライブラリ（http.server / ssl）のみで実装する。
クライアント直接 fetch のため CORS を全許可する（評価用・公開厳禁）。

スキーム: 既定 HTTPS（VULN_TLS!=0）。本体サイトと同じ自己署名証明書
（certs/vuln.crt・vuln.key を共有マウント）を読み込んで TLS 終端する。
VULN_TLS=0 のときは HTTP で待ち受ける。

    GET  /api/zip?code=1000001   -> {"code","pref","city","town","address"}
    GET  /healthz                -> {"status":"ok"}
    OPTIONS *                    -> 204（CORS プリフライト）
    不明な郵便番号               -> 404 {"error":"not found"}
"""

import json
import os
import re
import ssl
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

# 郵便番号（ハイフン無し7桁）-> 住所。
# 通常は build_data.py がビルド時に作る zipdata.json（日本郵便 KEN_ALL 全国データ）を読み込む。
# 取得できなかった場合に備え、主要都市の最小サンプルを内蔵フォールバックとして持つ。
SAMPLE_DB = {
    "1000001": ("東京都", "千代田区", "千代田"),
    "1000005": ("東京都", "千代田区", "丸の内"),
    "1050011": ("東京都", "港区", "芝公園"),
    "1500001": ("東京都", "渋谷区", "神宮前"),
    "1600022": ("東京都", "新宿区", "新宿"),
    "2200012": ("神奈川県", "横浜市西区", "みなとみらい"),
    "5300001": ("大阪府", "大阪市北区", "梅田"),
    "4600008": ("愛知県", "名古屋市中区", "栄"),
    "8120011": ("福岡県", "福岡市博多区", "博多駅前"),
    "0600001": ("北海道", "札幌市中央区", "北一条西"),
}


def _load_zip_db():
    path = os.environ.get("ZIP_DATA", "/app/zipdata.json")
    try:
        with open(path, encoding="utf-8") as f:
            d = json.load(f)
        if d:
            print("zipapi: %d 件の郵便番号データを読み込みました（%s）" % (len(d), path))
            return d
    except Exception as e:
        print("zipapi: %s を読めないため内蔵サンプルを使用します: %s" % (path, e))
    return dict(SAMPLE_DB)


ZIP_DB = _load_zip_db()

_FALSEY = ("0", "false", "no", "off", "")


class Handler(BaseHTTPRequestHandler):
    server_version = "VulnZipAPI/1.0"

    def _send(self, status, payload):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        # クライアント直接 fetch のための CORS 全許可（評価用）。
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "*")
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):  # noqa: N802 (http.server の命名規約)
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "*")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self):  # noqa: N802
        parsed = urlparse(self.path)
        if parsed.path == "/healthz":
            return self._send(200, {"status": "ok"})
        if parsed.path != "/api/zip":
            return self._send(404, {"error": "not found"})

        raw = (parse_qs(parsed.query).get("code", [""])[0])
        code = re.sub(r"\D", "", raw)  # ハイフン等を除去して数字のみ
        entry = ZIP_DB.get(code)
        if not entry:
            return self._send(404, {"error": "not found", "code": code})

        pref, city, town = entry
        return self._send(200, {
            "code": code,
            "pref": pref,
            "city": city,
            "town": town,
            "address": pref + city + town,
        })

    def log_message(self, fmt, *args):  # アクセスログは簡潔に
        print("zipapi %s - %s" % (self.address_string(), fmt % args))


def _tls_enabled():
    return os.environ.get("VULN_TLS", "0").strip().lower() not in _FALSEY


def _wait_for_cert(cert, key, timeout=30):
    """本体（vuln-suite）が共有 certs/ に証明書を生成するのを待つ。"""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if os.path.exists(cert) and os.path.exists(key):
            return True
        time.sleep(0.5)
    return os.path.exists(cert) and os.path.exists(key)


def main():
    host = os.environ.get("ZIP_API_HOST", "0.0.0.0")
    port = int(os.environ.get("ZIP_API_PORT", "8090"))
    httpd = ThreadingHTTPServer((host, port), Handler)

    scheme = "http"
    if _tls_enabled():
        cert = os.environ.get("ZIP_API_CERT", "/certs/vuln.crt")
        key = os.environ.get("ZIP_API_KEY", "/certs/vuln.key")
        if _wait_for_cert(cert, key):
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(cert, key)
            httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
            scheme = "https"
        else:
            print("zipapi: 証明書が見つからないため HTTP で起動します（%s / %s）" % (cert, key))

    print("zipapi listening on %s://%s:%d" % (scheme, host, port))
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        httpd.shutdown()


if __name__ == "__main__":
    main()

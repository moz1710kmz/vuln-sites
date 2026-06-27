"""
VulnBank / VulnEC - Intentionally Vulnerable Web Applications
For security scanner performance evaluation only.
DO NOT deploy in production or expose to the internet.
"""

import json
import os
import smtplib
import subprocess
import time
from datetime import datetime, timezone, timedelta
from importlib import import_module
from email.message import EmailMessage
from flask import (
    Flask, request, session, redirect, url_for,
    render_template, make_response, g, abort, jsonify
)
from flask_sock import Sock
from markupsafe import Markup
from core.database import get_db, init_db
from core.vulndata import VULN_MAP, WAF_BYPASS, vuln_in_site
from core import security_features
from core import harness
from core import jwtutil
from core.envfile import load_env_file

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
load_env_file(BASE_DIR)

app = Flask(__name__)
# [VULN] Weak hardcoded secret key — session tokens are predictable
app.secret_key = "secret123"

# [VULN] セッション Cookie に保護属性を付けない（挙動は変えず、属性だけ欠落させる）。
#   COOKIE-1 HttpOnly 無し: JavaScript から document.cookie でセッションを読めるため、
#            反射/格納 XSS（XSS-R / XSS-S）と組み合わせてセッションを窃取できる。
#   COOKIE-2 Secure 無し: 既定は HTTPS だが Secure が無いため、平文 HTTP に誘導されると
#            セッション Cookie が平文で送信され漏えいしうる（CWE-1004 / CWE-614）。
# Cookie 自体は通常どおり送受信されるのでログイン等の動作は壊れない。
app.config["SESSION_COOKIE_HTTPONLY"] = False   # 既定(True)を意図的に無効化
app.config["SESSION_COOKIE_SECURE"] = False     # HTTPS でも Secure 属性を付けない

# VulnBank サポートチャット用の生 WebSocket（/support/ws）。脆弱性は WS ハンドラに集中。
sock = Sock(app)


def _int_env(name, default):
    try:
        return int(os.environ.get(name, str(default)) or default)
    except ValueError:
        return default


# [設定] 有効化するバリア（スキャナ評価用）。
# VULN_FEATURES=waf,otp,email_verify のように個別指定（コントロールパネルから注入）。
# 後方互換: 未指定なら DIFFICULTY=hard→全機能 / easy→なし。
# 脆弱性そのものはフラグに関わらず不変で、到達・発火の難易度だけが上がる。
# バリアの実体は security_features.py に隔離。
app.config["VULN_FEATURES"] = security_features.parse_features(os.environ)
app.config["VULN_SITE"] = os.environ.get("VULN_SITE", "all").strip().lower() or "all"
app.config["VULN_DELIVERY"] = os.environ.get("VULN_DELIVERY", "dev_inbox").strip().lower() or "dev_inbox"
app.config["SMTP_HOST"] = os.environ.get("SMTP_HOST", "")
app.config["SMTP_PORT"] = _int_env("SMTP_PORT", 587)
app.config["SMTP_USERNAME"] = os.environ.get("SMTP_USERNAME", "")
app.config["SMTP_PASSWORD"] = os.environ.get("SMTP_PASSWORD", "")
app.config["SMTP_FROM"] = os.environ.get("SMTP_FROM", "vulnbank@example.test")
app.config["SMTP_TLS"] = os.environ.get("SMTP_TLS", "1").strip().lower() in ("1", "true", "yes", "on")
app.config["AWS_REGION"] = os.environ.get("AWS_REGION", "ap-northeast-1")
app.config["AWS_ACCESS_KEY_ID"] = os.environ.get("AWS_ACCESS_KEY_ID", "")
app.config["AWS_SECRET_ACCESS_KEY"] = os.environ.get("AWS_SECRET_ACCESS_KEY", "")
app.config["SES_FROM"] = os.environ.get("SES_FROM", app.config["SMTP_FROM"])

MANUALS_DIR = os.path.join(BASE_DIR, "manuals")
UPLOADS_DIR = os.path.join(BASE_DIR, "uploads")

SITE_LABELS = {"all": "VulnBank", "bank": "VulnBank", "ec": "VulnEC",
               "board": "VulnBoard", "graphql": "VulnGraph"}
COMMON_PATH_PREFIXES = (
    "/login", "/login/2fa", "/register", "/logout", "/verify",
    "/dev/inbox", "/vuln-map", "/vuln-map.json",
)
BANK_PATH_PREFIXES = ("/profile", "/change-password", "/transfer", "/support", "/admin/users", "/admin/announcements", "/announcements")
EC_PATH_PREFIXES = (
    "/blog", "/shop", "/orders",
    "/cart", "/checkout",   # 多段チェックアウト（カート→住所→支払い→確認）
    "/admin",
    "/change-password",   # 自分のパスワード変更（Bank と共通のアカウント機能）
    "/mypage",            # マイページ（EC 単独起動で公開するために必須）
)
BOARD_PATH_PREFIXES = ("/api",)
GRAPHQL_PATH_PREFIXES = ("/graphql",)


@app.template_filter("yen")
def yen(value):
    """金額を3桁カンマ区切り・小数点なしで整形する（例: 50000 -> 50,000）。"""
    try:
        return "{:,.0f}".format(float(value))
    except (TypeError, ValueError):
        return value


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _session_table():
    """セッションに記録されたログイン元サイトに基づいてユーザーテーブル名を返す。"""
    site = session.get("user_site") or current_site()
    if site == "ec":
        return "ec_users"
    # bank, all, graphql → bank_users
    return "bank_users"


def _login_table():
    """現在のサイト設定に基づいてログイン先テーブル名を返す。"""
    site = current_site()
    if site == "ec":
        return "ec_users"
    return "bank_users"


def current_user():
    uid = session.get("user_id")
    if not uid:
        return None
    db = get_db()
    table = _session_table()
    user = db.execute(f"SELECT * FROM {table} WHERE id = ?", (uid,)).fetchone()
    db.close()
    return user


def current_site():
    site = app.config.get("VULN_SITE", "all")
    return site if site in ("all", "bank", "ec", "board", "graphql") else "all"


def site_label():
    return SITE_LABELS.get(current_site(), "VulnBank")


def _login_tmpl():
    return "bank/login.html" if current_site() == "bank" else "common/login.html"


def _register_tmpl():
    return "bank/register.html" if current_site() == "bank" else "common/register.html"


def site_vulns():
    site = current_site()
    if site == "all":
        return VULN_MAP
    return [v for v in VULN_MAP if vuln_in_site(v, site)]


def route_allowed_for_site(path):
    site = current_site()
    if site == "all" or path == "/" or path.startswith("/static") or path == "/favicon.ico":
        return True
    if path.startswith(COMMON_PATH_PREFIXES):
        return True
    if site == "bank":
        return path.startswith(BANK_PATH_PREFIXES)
    if site == "ec":
        return path.startswith(EC_PATH_PREFIXES)
    if site == "board":
        return path.startswith(BOARD_PATH_PREFIXES)
    if site == "graphql":
        return path.startswith(GRAPHQL_PATH_PREFIXES)
    return True


def send_notification(to_addr, subject, body):
    """
    評価用通知の配送口。

    dev_inbox では DB に保存された認証リンク/OTP を /dev/inbox から取得するため、
    ここでは何もしない。smtp/ses では実際にメール送信する。
    """
    delivery = app.config.get("VULN_DELIVERY")
    if delivery == "dev_inbox":
        return True, None
    if not to_addr:
        return False, "宛先メールアドレスがありません。"
    if delivery == "ses":
        return send_notification_via_ses(to_addr, subject, body)

    return send_notification_via_smtp(to_addr, subject, body)


def send_notification_via_smtp(to_addr, subject, body):
    host = app.config.get("SMTP_HOST", "")
    if not host:
        return False, "SMTP サーバが設定されていません。"

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = app.config.get("SMTP_FROM", "vulnbank@example.test")
    msg["To"] = to_addr
    msg.set_content(body)

    try:
        with smtplib.SMTP(host, app.config.get("SMTP_PORT", 587), timeout=10) as smtp:
            if app.config.get("SMTP_TLS"):
                smtp.starttls()
            username = app.config.get("SMTP_USERNAME", "")
            if username:
                smtp.login(username, app.config.get("SMTP_PASSWORD", ""))
            smtp.send_message(msg)
        return True, None
    except Exception as e:
        return False, "SMTP 送信に失敗しました: %s" % e


def send_notification_via_ses(to_addr, subject, body):
    try:
        boto3 = import_module("boto3")
    except ImportError:
        return False, "SES 送信には boto3 が必要です。requirements.txt をインストールしてください。"

    kwargs = {"region_name": app.config.get("AWS_REGION", "ap-northeast-1")}
    access_key = app.config.get("AWS_ACCESS_KEY_ID", "")
    secret_key = app.config.get("AWS_SECRET_ACCESS_KEY", "")
    if access_key or secret_key:
        kwargs["aws_access_key_id"] = access_key
        kwargs["aws_secret_access_key"] = secret_key

    try:
        ses = boto3.client("ses", **kwargs)
        ses.send_email(
            Source=app.config.get("SES_FROM") or app.config.get("SMTP_FROM", "vulnbank@example.test"),
            Destination={"ToAddresses": [to_addr]},
            Message={
                "Subject": {"Data": subject, "Charset": "UTF-8"},
                "Body": {"Text": {"Data": body, "Charset": "UTF-8"}},
            },
        )
        return True, None
    except Exception as e:
        return False, "SES 送信に失敗しました: %s" % e


@app.after_request
def log_request(response):
    """[ハーネス] 全リクエストを request_log に記録し、攻撃シグネチャでタグ付けする。"""
    try:
        if request.path.startswith("/static") or request.path == "/favicon.ico":
            return response
        params = {}
        params.update(request.args.to_dict(flat=True))
        try:
            params.update(request.form.to_dict(flat=True))
        except Exception:
            pass
        matched = harness.classify(request.method, request.path, params)

        def _trunc(s, n=300):
            s = s or ""
            return s if len(s) <= n else s[:n] + "…"

        db = get_db()
        db.execute(
            "INSERT INTO request_log (site, method, path, query, form, status, remote_addr, matched) "
            "VALUES (?,?,?,?,?,?,?,?)",
            (current_site(), request.method, request.path,
             _trunc(request.query_string.decode("latin1")),
             _trunc("&".join(f"{k}={v}" for k, v in request.form.to_dict(flat=True).items())),
             response.status_code, request.remote_addr, ",".join(matched)),
        )
        db.commit()
        db.close()
    except Exception:
        pass
    return response


@app.before_request
def site_guard():
    """Bank/EC の単独起動時は、そのサイトに属するルートだけを公開する。"""
    if not route_allowed_for_site(request.path):
        abort(404)


@app.before_request
def waf_guard():
    """
    [HARD] WAF風入力フィルタ（easy では no-op）。
    リクエストの全パラメータ値を素朴なブラックリストで検査し、一致したら 403。
    意図的に回避可能（security_features.WAF_BLOCKLIST と WAF_BYPASS 参照）。
    """
    if security_features.waf_blocks(request.values.values()):
        return render_template("common/waf_blocked.html"), 403


@app.before_request
def honeypot_guard():
    """[HARD] ハニーポット: 隠しフィールドが埋まっていれば Bot とみなしブロック。"""
    if request.path.startswith(("/api/", "/graphql")):
        return  # JSON API（Bearer / GraphQL）は HTML フォーム用のバリアの対象外。
    if (request.method == "POST" and security_features.feature("honeypot")
            and security_features.honeypot_triggered(request.form)):
        return render_template(
            "common/blocked.html",
            title="🤖 Bot を検知しました",
            detail="自動化ツールによる送信と判断しました。(403)",
        ), 403


@app.before_request
def csrf_guard():
    """[HARD] CSRF トークン: 状態変更 POST に有効な csrf_token を要求する。"""
    if request.path.startswith(("/api/", "/graphql")):
        return  # JSON API（Bearer / GraphQL）はフォーム用 CSRF トークンの対象外。
        # 注: GraphQL は GET でミューテーションを受理する点が GQL-7（CSRF）の脆弱性。
    if request.method == "POST" and security_features.feature("csrf"):
        if not security_features.csrf_valid(request.form):
            return render_template(
                "common/blocked.html",
                title="⛔ CSRF 検証に失敗しました",
                detail="csrf_token が無効です。フォームから取得したトークンを送信してください。(403)",
            ), 403


@app.teardown_request
def _close_leaked_dbs(exc):
    """リクエスト中に開いた DB 接続を確実に閉じる（例外時でも呼ばれる）。
    手動 db.close() 済みでも close() は冪等なので二重クローズは無害。
    debug=True のデバッガがフレームを保持しても FD を握ったままにならない。"""
    for conn in g.pop("_open_dbs", []):
        try:
            conn.close()
        except Exception:
            pass


@app.template_global()
def csrf_field():
    """csrf 有効時のみ、フォームに埋める hidden トークンを返す。"""
    if security_features.feature("csrf"):
        return Markup('<input type="hidden" name="csrf_token" value="%s">'
                      % security_features.get_csrf_token())
    return ""


@app.template_global()
def cart_count():
    """ナビ表示用。セッションカート内の総数量を返す（未ログインでも保持）。"""
    return sum(int(i.get("qty", 0)) for i in session.get("cart", []))


@app.template_global()
def honeypot_field():
    """honeypot 有効時のみ、人間には見えない囮フィールドを返す。"""
    if security_features.feature("honeypot"):
        return Markup(
            '<input type="text" name="%s" value="" autocomplete="off" tabindex="-1" '
            'style="position:absolute;left:-9999px;width:1px;height:1px;opacity:0;" '
            'aria-hidden="true">' % security_features.HONEYPOT_FIELD
        )
    return ""


# ---------------------------------------------------------------------------
# Home
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    user = current_user()
    if current_site() == "board":
        # タスク管理 SPA（HTML）。ログイン後は JWT を localStorage に保持し /api/* を叩く。
        return render_template("board/api_spa.html", user=user)
    if current_site() == "graphql":
        # GraphQL の薄い SPA（裏で /graphql にクエリを投げる）。
        return render_template("graphql/graphql_spa.html", user=user)
    if current_site() == "bank":
        db = get_db()
        logs = []
        balance_series = []  # 案4: 残高推移グラフ用（利用者のみ）
        # 残高・口座サマリー・振込履歴は利用者(role=user)向け。staff/admin には出さない。
        if user and user["role"] == "user":
            logs = db.execute(
                "SELECT * FROM transfer_logs WHERE user_id=? ORDER BY created_at DESC LIMIT 10",
                (user["id"],),
            ).fetchall()
            # 案4: 残高推移グラフ用に balance_after の時系列を抽出（古い順に並べ直す）。
            # 振込履歴から直接 balance_after を取り出す。0 件時は空リストのままグラフ非表示。
            if logs:
                balance_series = [row["balance_after"] for row in reversed(list(logs))]
        db.close()
        last_login = datetime.now(timezone(timedelta(hours=9))).strftime("%Y-%m-%d %H:%M")
        return render_template("bank/bank_index.html", user=user, logs=logs,
                               now=last_login, balance_series=balance_series)
    db = get_db()
    posts = db.execute(
        "SELECT posts.*, ec_users.username FROM posts JOIN ec_users ON posts.author_id=ec_users.id ORDER BY created_at DESC"
    ).fetchall()
    db.close()
    featured = get_products()[:3]
    return render_template("ec/index.html", user=user, posts=posts, featured=featured)


# ---------------------------------------------------------------------------
# Auth — SQL Injection + Plaintext passwords + No rate-limit
# ---------------------------------------------------------------------------

@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        # [HARD] レート制限/アカウントロック（フラグ無効時は素通り）
        if security_features.feature("ratelimit") and security_features.login_locked(username):
            error = "試行回数が多すぎます。しばらく待ってから再試行してください。"
            return render_template(_login_tmpl(), error=error), 429

        db = get_db()
        # [VULN-SQLi] String concatenation — no parameterized query
        _tbl = _login_table()
        query = f"SELECT * FROM {_tbl} WHERE username='{username}' AND password='{password}'"
        try:
            user = db.execute(query).fetchone()
        except Exception as e:
            # [VULN] SQL error message leaked to the user
            error = f"Database error: {e}"
            db.close()
            return render_template(_login_tmpl(), error=error)
        db.close()

        if user:
            # [HARD] メール未認証アカウントはログイン不可（フラグ無効時は素通り）。
            # ※ SQLi で取得される既存ユーザー(admin 等)は認証済みなので回避は依然成立する。
            if security_features.feature("email_verify") and not user["email_verified"]:
                error = "メールアドレスが未認証です。確認メールのリンクから認証してください。"
                return render_template(_login_tmpl(), error=error)
            if security_features.feature("ratelimit"):
                security_features.clear_login_failures(username)
            # [HARD] 2要素認証（TOTP相当）: パスワード一致後にワンタイムコードを要求。
            if security_features.feature("totp"):
                code = security_features.new_otp()
                db = get_db()
                db.execute("DELETE FROM otps WHERE user_id=? AND purpose='login'", (user["id"],))
                db.execute("INSERT INTO otps (user_id, code, purpose) VALUES (?,?, 'login')",
                           (user["id"], code))
                db.commit()
                db.close()
                _, delivery_error = send_notification(
                    user["email"],
                    "VulnBank ログイン確認コード",
                    "ログイン確認コード: %s\n\nこのコードを /login/2fa に入力してください。" % code,
                )
                session["pending_login"] = user["id"]
                return render_template(_login_tmpl(), totp_required=True,
                                       delivery_error=delivery_error)
            _complete_login(user)
            return redirect(url_for("index"))
        else:
            if security_features.feature("ratelimit"):
                security_features.record_login_failure(username)
            error = "Invalid credentials."

    return render_template(_login_tmpl(), error=error)


def _complete_login(user):
    # [VULN] Session fixation — session ID not rotated on login
    session["user_id"] = user["id"]
    session["username"] = user["username"]
    session["role"] = user["role"] if "role" in user.keys() else "user"
    session["user_site"] = current_site()  # テーブル判定に使う


@app.route("/login/2fa", methods=["POST"])
def login_2fa():
    """[HARD] 2FA コード確認（totp 有効時）。コードは配送設定に応じて取得できる。"""
    uid = session.get("pending_login")
    if not uid:
        return redirect(url_for("login"))
    otp = request.form.get("otp", "")
    db = get_db()
    row = db.execute(
        "SELECT code FROM otps WHERE user_id=? AND purpose='login' ORDER BY id DESC LIMIT 1",
        (uid,),
    ).fetchone()
    if not row or row["code"] != otp:
        db.close()
        return render_template(_login_tmpl(), totp_required=True,
                               error="コードが正しくありません。")
    user = db.execute(f"SELECT * FROM {_login_table()} WHERE id=?", (uid,)).fetchone()
    db.execute("DELETE FROM otps WHERE user_id=? AND purpose='login'", (uid,))
    db.commit()
    db.close()
    session.pop("pending_login", None)
    _complete_login(user)
    return redirect(url_for("index"))


@app.route("/register", methods=["GET", "POST"])
def register():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        email = request.form.get("email", "")

        _tbl = _login_table()
        db = get_db()
        existing = db.execute(f"SELECT id FROM {_tbl} WHERE username=?", (username,)).fetchone()
        if existing:
            error = "Username already taken."
        elif security_features.feature("email_verify"):
            # [HARD] メール認証付き登録: 未認証状態で作成し、トークンを発行。
            # 認証リンクは配送設定に応じて /dev/inbox または SMTP で取得できる。
            token = security_features.new_token()
            # [VULN] Password stored in plaintext（easy/hard 共通）
            db.execute(
                f"INSERT INTO {_tbl} (username, password, email, email_verified, verify_token) VALUES (?,?,?,0,?)",
                (username, password, email, token),
            )
            db.commit()
            db.close()
            verify_url = url_for("verify_email", token=token, _external=True)
            _, delivery_error = send_notification(
                email,
                "VulnBank メールアドレス確認",
                "以下のリンクからメールアドレスを確認してください。\n\n%s" % verify_url,
            )
            return render_template(_register_tmpl(), pending_email=email,
                                   delivery_error=delivery_error)
        else:
            # [EASY] 従来どおり即時有効・平文PW保存
            db.execute(
                f"INSERT INTO {_tbl} (username, password, email) VALUES (?,?,?)",
                (username, password, email),
            )
            db.commit()
            db.close()
            return redirect(url_for("login"))
        db.close()

    return render_template(_register_tmpl(), error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


# ---------------------------------------------------------------------------
# [HARD] メール認証フロー（easy では未使用）
# ---------------------------------------------------------------------------

@app.route("/verify")
def verify_email():
    """確認リンク。verify_token が一致すればメール認証済みにする。"""
    token = request.args.get("token", "")
    user = None
    if token:
        db = get_db()
        tbl = _login_table()
        user = db.execute(f"SELECT * FROM {tbl} WHERE verify_token=?", (token,)).fetchone()
        if user:
            db.execute(
                f"UPDATE {tbl} SET email_verified=1, verify_token=NULL WHERE id=?",
                (user["id"],),
            )
            db.commit()
        db.close()
    return render_template("common/verify.html", ok=bool(user),
                           username=user["username"] if user else None)


@app.route("/dev/inbox")
def dev_inbox():
    """
    [抜け道] 実メールサーバの代わり（MailHog 相当）。
    保留中のメール認証リンク・OTP を一覧表示し、自動スキャナ/テストが多段フローを完走できるようにする。
    メール認証 / OTP / 2FA のいずれかが有効なときだけ使える（すべて無効なら 404）。
    """
    if app.config.get("VULN_DELIVERY") != "dev_inbox":
        abort(404)
    if not (security_features.feature("email_verify") or security_features.feature("otp")
            or security_features.feature("totp")):
        abort(404)
    db = get_db()
    tbl = _login_table()
    pending = db.execute(
        f"SELECT username, email, verify_token FROM {tbl} "
        "WHERE email_verified=0 AND verify_token IS NOT NULL ORDER BY id DESC"
    ).fetchall()
    otps = db.execute(
        f"SELECT otps.code, otps.purpose, otps.created_at, {tbl}.username "
        f"FROM otps JOIN {tbl} ON otps.user_id={tbl}.id ORDER BY otps.id DESC"
    ).fetchall()
    db.close()
    return render_template("common/dev_inbox.html", pending=pending, otps=otps)


# ---------------------------------------------------------------------------
# Blog 記事検索 — Reflected XSS + SQL Injection (UNION-based)
# ---------------------------------------------------------------------------

@app.route("/blog/search")
def blog_search():
    user = current_user()
    query = request.args.get("q", "")
    results = []
    sql_error = None

    if query:
        db = get_db()
        # [VULN-SQLi] UNION injection possible here（posts を生SQLで検索）
        sql = f"SELECT id, title, body FROM posts WHERE title LIKE '%{query}%' OR body LIKE '%{query}%'"
        try:
            results = db.execute(sql).fetchall()
        except Exception as e:
            sql_error = str(e)
        db.close()

    # [VULN-XSS Reflected] query rendered without escaping via Markup()
    return render_template("ec/blog_search.html", user=user, query=Markup(query), results=results, sql_error=sql_error)


# ---------------------------------------------------------------------------
# Blog — Stored XSS
# ---------------------------------------------------------------------------

@app.route("/blog")
def blog():
    user = current_user()
    db = get_db()
    posts = db.execute(
        "SELECT posts.*, ec_users.username FROM posts JOIN ec_users ON posts.author_id=ec_users.id ORDER BY created_at DESC"
    ).fetchall()
    db.close()
    return render_template("ec/blog.html", user=user, posts=posts)


@app.route("/blog/new", methods=["GET", "POST"])
def new_post():
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    # 機能レベル認可: 記事の投稿は店舗担当者(staff)・管理者(admin)のみ。利用者(user)は不可。
    if user["role"] not in ("staff", "admin"):
        abort(403)
    if request.method == "POST":
        title = request.form.get("title", "")
        body = request.form.get("body", "")
        db = get_db()
        db.execute("INSERT INTO posts (author_id, title, body) VALUES (?,?,?)", (user["id"], title, body))
        db.commit()
        db.close()
        return redirect(url_for("blog"))
    return render_template("ec/new_post.html", user=user)


@app.route("/blog/<int:post_id>")
def blog_post(post_id):
    user = current_user()
    db = get_db()
    post = db.execute(
        "SELECT posts.*, ec_users.username FROM posts JOIN ec_users ON posts.author_id=ec_users.id WHERE posts.id=?",
        (post_id,),
    ).fetchone()
    if not post:
        db.close()
        abort(404)
    comments = db.execute(
        "SELECT * FROM comments WHERE post_id=? ORDER BY created_at ASC", (post_id,)
    ).fetchall()
    db.close()
    return render_template("ec/blog_post.html", user=user, post=post, comments=comments)


@app.route("/blog/<int:post_id>/comment", methods=["POST"])
def add_comment(post_id):
    author = request.form.get("author", "Anonymous")
    body = request.form.get("body", "")
    db = get_db()
    # [VULN-XSS Stored] body inserted raw, rendered without escaping in template
    db.execute("INSERT INTO comments (post_id, author, body) VALUES (?,?,?)", (post_id, author, body))
    db.commit()
    db.close()
    return redirect(url_for("blog_post", post_id=post_id))


# ---------------------------------------------------------------------------
# ブログ記事の管理（店舗担当者/管理者向け）— [VULN AUTHZ-4] 機能レベル認可の欠落（BFLA）
#   ナビは staff/admin にしか編集リンクを出さないが、サーバ側はロールも所有者も
#   検証しないため、利用者(user)でも任意の記事を改ざん/削除できる（CWE-862）。
# ---------------------------------------------------------------------------

@app.route("/blog/<int:post_id>/edit", methods=["GET", "POST"])
def blog_edit(post_id):
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    db = get_db()
    post = db.execute("SELECT * FROM posts WHERE id=?", (post_id,)).fetchone()
    if not post:
        db.close()
        abort(404)
    if request.method == "POST":
        title = request.form.get("title", "")
        body = request.form.get("body", "")
        # [VULN AUTHZ-4] ロール/所有者検証なしで誰でも記事を改ざんできる。
        db.execute("UPDATE posts SET title=?, body=? WHERE id=?", (title, body, post_id))
        db.commit()
        db.close()
        return redirect(url_for("blog_post", post_id=post_id))
    db.close()
    return render_template("ec/blog_edit.html", user=user, post=post)


@app.route("/blog/<int:post_id>/delete", methods=["POST"])
def blog_delete(post_id):
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    # [VULN AUTHZ-4] ロール/所有者検証なしで誰でも記事を削除できる。
    db = get_db()
    db.execute("DELETE FROM posts WHERE id=?", (post_id,))
    db.commit()
    db.close()
    return redirect(url_for("blog"))


# ---------------------------------------------------------------------------
# Profile — IDOR
# ---------------------------------------------------------------------------

@app.route("/profile")
def profile_self():
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    return redirect(url_for("profile", user_id=user["id"]))


@app.route("/profile/<int:user_id>")
def profile(user_id):
    viewer = current_user()
    db = get_db()
    # [VULN-IDOR] No ownership check — any authenticated user can view any profile
    target = db.execute("SELECT * FROM bank_users WHERE id=?", (user_id,)).fetchone()
    db.close()
    if not target:
        abort(404)
    return render_template("bank/profile.html", user=viewer, target=target)


# ---------------------------------------------------------------------------
# Change Password — CSRF
# ---------------------------------------------------------------------------

@app.route("/change-password", methods=["GET", "POST"])
def change_password():
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    msg = None
    if request.method == "POST":
        new_pass = request.form.get("new_password", "")
        # [VULN-CSRF] No CSRF token verification
        db = get_db()
        db.execute(f"UPDATE {_session_table()} SET password=? WHERE id=?", (new_pass, user["id"]))
        db.commit()
        db.close()
        msg = "Password changed successfully."
    return render_template("bank/change_password.html", user=user, msg=msg)


# ---------------------------------------------------------------------------
# Transfer — CSRF + Business Logic (negative amount)
# ---------------------------------------------------------------------------

def do_transfer(db, from_id, to_user_id, amount):
    """
    実際の送金処理（easy/hard 共通の単一ソース）。
    [VULN-BizLogic] 負の金額を弾かないため、相手から残高を奪取できる。
    成功時 (msg, None) / 失敗時 (None, error) を返す。
    """
    to_user = db.execute("SELECT * FROM bank_users WHERE id=?", (to_user_id,)).fetchone()
    me = db.execute("SELECT * FROM bank_users WHERE id=?", (from_id,)).fetchone()
    if not to_user:
        return None, "送金先が見つかりません。"
    if me["balance"] < amount:
        return None, "残高が不足しています。"
    db.execute("UPDATE bank_users SET balance = balance - ? WHERE id=?", (amount, from_id))
    db.execute("UPDATE bank_users SET balance = balance + ? WHERE id=?", (amount, to_user_id))
    # 振込履歴を記録: 出金側(from)と入金側(to)の 2 行。
    # [NOTE] amount のバリデーションなし（BIZ-1 保持）: 負数もそのまま記録される。
    from_balance = db.execute("SELECT balance FROM bank_users WHERE id=?", (from_id,)).fetchone()["balance"]
    to_balance = db.execute("SELECT balance FROM bank_users WHERE id=?", (to_user_id,)).fetchone()["balance"]
    db.execute(
        "INSERT INTO transfer_logs (user_id, counterparty, direction, amount, balance_after)"
        " VALUES (?,?,?,?,?)",
        (from_id, to_user["username"], "out", amount, from_balance),
    )
    db.execute(
        "INSERT INTO transfer_logs (user_id, counterparty, direction, amount, balance_after)"
        " VALUES (?,?,?,?,?)",
        (to_user_id, me["username"], "in", amount, to_balance),
    )
    db.commit()
    # 案8: 実在風の一意な受付番号（TRN-YYYYMMDD-XXXXXX）を生成して成功メッセージに付与する。
    import uuid
    today = datetime.now(timezone(timedelta(hours=9))).strftime("%Y%m%d")
    trn_suffix = uuid.uuid4().hex[:6].upper()
    receipt_no = f"TRN-{today}-{trn_suffix}"
    return (
        f"{to_user['username']} さんへ ¥{amount:,.0f} を送金しました。"
        f" 受付番号: {receipt_no}",
        None,
    )


@app.route("/transfer", methods=["GET", "POST"])
def transfer():
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    # 送金は利用者(user)の機能。サポート/管理者は送金できない（機能を持たない）。
    if user["role"] != "user":
        abort(403)
    db = get_db()
    # 送金先候補は利用者(user)のみ（管理者・サポート口座には振り込めない）。
    all_users = db.execute("SELECT id, username FROM bank_users WHERE role='user' AND id != ?", (user["id"],)).fetchall()
    msg = None
    error = None

    if request.method == "POST":
        to_user_id = request.form.get("to_user_id", type=int)
        # [VULN-BizLogic] Negative amount allows stealing funds
        amount = request.form.get("amount", type=float, default=0)
        # [VULN-CSRF] No CSRF token
        if security_features.feature("otp"):
            # [HARD] 送金前に SMS/OTP 確認を要求する（2段階）。
            # コードは配送設定に応じて /dev/inbox または SMTP で取得できる。
            code = security_features.new_otp()
            db.execute("DELETE FROM otps WHERE user_id=? AND purpose='transfer'", (user["id"],))
            db.execute("INSERT INTO otps (user_id, code, purpose) VALUES (?,?, 'transfer')",
                       (user["id"], code))
            db.commit()
            db.close()
            _, delivery_error = send_notification(
                user["email"],
                "VulnBank 送金 OTP コード",
                "送金確認コード: %s\n\nこのコードを送金確認画面に入力してください。" % code,
            )
            # 保留中の送金内容はセッションに保持し、確認ステップで実行する
            session["pending_transfer"] = {"to_user_id": to_user_id, "amount": amount}
            return render_template("bank/transfer.html", user=user, all_users=all_users,
                                   otp_required=True, delivery_error=delivery_error)
        # [EASY] 「送金内容を確認」からの遷移は、実際の振込先・金額を表示するだけで実行しない。
        # action なしの単発 POST（確認画面の「この内容で送金する」や外部からの直 POST）は
        # 従来どおり即時実行する → CSRF-2 / BIZ-1 を保持。
        if request.form.get("action") == "confirm":
            to_user = db.execute("SELECT username FROM bank_users WHERE id=?", (to_user_id,)).fetchone()
            db.close()
            return render_template("bank/transfer.html", user=user, all_users=all_users,
                                   confirm_view=True, confirm_to_id=to_user_id,
                                   confirm_to_name=(to_user["username"] if to_user else None),
                                   confirm_amount=amount)
        # [EASY] 従来どおり即時実行
        msg, error = do_transfer(db, user["id"], to_user_id, amount)
        user = db.execute("SELECT * FROM bank_users WHERE id=?", (user["id"],)).fetchone()
        session["username"] = user["username"]

    db.close()
    return render_template("bank/transfer.html", user=user, all_users=all_users,
                           msg=msg, error=error)


@app.route("/transfer/confirm", methods=["POST"])
def transfer_confirm():
    """[HARD] 送金 OTP の確認ステップ。easy では使用しない。"""
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    # 送金は利用者(user)のみ（transfer と同じ制限を OTP 確認ステップにも適用）。
    if user["role"] != "user":
        abort(403)
    db = get_db()
    all_users = db.execute("SELECT id, username FROM bank_users WHERE role='user' AND id != ?", (user["id"],)).fetchall()
    msg = None
    error = None

    pending = session.get("pending_transfer")
    otp = request.form.get("otp", "")
    row = db.execute(
        "SELECT code FROM otps WHERE user_id=? AND purpose='transfer' ORDER BY id DESC LIMIT 1",
        (user["id"],),
    ).fetchone()

    if not pending:
        error = "保留中の送金がありません。最初からやり直してください。"
    elif not row or row["code"] != otp:
        # OTP 不一致: 保留を保持したまま再入力させる
        db.close()
        return render_template("bank/transfer.html", user=user, all_users=all_users,
                               otp_required=True, error="OTP コードが正しくありません。")
    else:
        # OTP 一致: 保留中の送金を実行（負数送金などの脆弱性はここで成立）
        msg, error = do_transfer(db, user["id"], pending["to_user_id"], pending["amount"])
        db.execute("DELETE FROM otps WHERE user_id=? AND purpose='transfer'", (user["id"],))
        db.commit()
        session.pop("pending_transfer", None)

    user = db.execute("SELECT * FROM bank_users WHERE id=?", (user["id"],)).fetchone()
    session["username"] = user["username"]
    db.close()
    return render_template("bank/transfer.html", user=user, all_users=all_users, msg=msg, error=error)


@app.route("/transfer/lookup", methods=["GET"])
def transfer_lookup():
    """案1: 口座番号（ゼロ埋め8桁 = user.id）から受取人名を返す照合 API。
    認証不要で参照できる点は意図的（IDOR 的な情報露出・利便性優先の設計ミス）。
    """
    account = request.args.get("account", "").strip()
    if not account:
        return jsonify({"error": "口座番号を指定してください。"}), 400
    try:
        uid = int(account)
    except ValueError:
        return jsonify({"error": "口座番号は数値で指定してください。"}), 400
    db = get_db()
    row = db.execute(
        "SELECT id, username FROM bank_users WHERE id=? AND role='user'", (uid,)
    ).fetchone()
    db.close()
    if not row:
        return jsonify({"error": "該当する口座が見つかりません。"}), 404
    return jsonify({"user_id": row["id"], "username": row["username"]})


# ---------------------------------------------------------------------------
# Support chat — 生 WebSocket（VulnBank）。意図的脆弱性を集中させる。
#   WS-1 CSWSH        : ハンドシェイクで Origin を検証しない（Cookie セッション認証）
#   WS-2 格納XSS      : 受信本文を無加工で全接続へ配信（クライアントは innerHTML 描画）
#   WS-3 Room IDOR    : ?room=<id> の所有者確認なし。任意ルームの履歴を読める
#   WS-4 Spoofing     : クライアント送信の sender を検証せず信用する
# ---------------------------------------------------------------------------

@app.template_global()
def support_room_for(user):
    """顧客 1 名 = 1 ルーム。ルーム ID は 'R-<1000+user_id>'。"""
    return "R-%d" % (1000 + user["id"]) if user else "R-guest"


def support_display_name(user):
    """サポートチャットの既定の発言者名。
    サポート担当(staff/admin)が「サポート管理」コンソールから発言する場合は
    表示名を「サポート」に統一する。一般利用者は username、未認証は guest。
    ※ WS-4 はこの既定名を上書きするクライアント指定 sender を無検証で採用する点なので、
       ここで既定名を決めても送信者なりすましは保持される。
    """
    if user and user["role"] in ("staff", "admin"):
        return "サポート"
    if user:
        return user["username"]
    return "guest"


def support_history(db, room_id):
    """指定ルームの会話履歴を返す（所有者確認はしない＝WS-3 の土台）。"""
    return db.execute(
        "SELECT sender_name, body, created_at FROM chat_messages "
        "WHERE room_id=? ORDER BY id", (room_id,),
    ).fetchall()


def support_save(db, room_id, sender_id, sender_name, body):
    """受信本文をそのまま保存する（サニタイズしない＝WS-2 の土台）。"""
    db.execute(
        "INSERT INTO chat_messages (room_id, sender_id, sender_name, body) VALUES (?,?,?,?)",
        (room_id, sender_id, sender_name, body),
    )
    db.commit()


def _support_msg(room_id, sender_name, body, ts=None):
    return json.dumps({"room": room_id, "sender": sender_name, "body": body,
                       "ts": ts or datetime.now(timezone(timedelta(hours=9))).strftime("%H:%M")})


# 接続レジストリ: room_id -> 接続中 WebSocket の集合。配信に使う（プロセス内）。
_support_clients = {}


@app.route("/support")
def support():
    """顧客サポートチャット入口。専用画面ではなくプロフィール上の右下ウィジェットへ案内する。"""
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    room = request.args.get("room") or support_room_for(user)
    return redirect(url_for("profile", user_id=user["id"], room=room))


@app.route("/support/admin")
def support_admin():
    """サポート担当コンソール（support/admin）。全ルーム一覧と会話を閲覧・返信できる。"""
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    if user["role"] not in ("staff", "admin"):
        abort(403)
    db = get_db()
    rooms = [r["room_id"] for r in db.execute(
        "SELECT room_id, MAX(id) AS last FROM chat_messages GROUP BY room_id ORDER BY last DESC"
    ).fetchall()]
    selected = request.args.get("room") or (rooms[0] if rooms else support_room_for(user))
    history = support_history(db, selected)
    db.close()
    return render_template("bank/support_admin.html", user=user, rooms=rooms,
                           room=selected, history=history)


# ---------------------------------------------------------------------------
# お知らせ利用者向け閲覧ページ（VulnBank）— 独立ページとして分離。
#   要ログイン。訪問すると既読状態を session に記録し未読バッヂを消す。
# ---------------------------------------------------------------------------

@app.route("/announcements")
def announcements():
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    db = get_db()
    ann_list = db.execute(
        "SELECT * FROM bank_announcements ORDER BY published_at DESC, id DESC"
    ).fetchall()
    db.close()
    # 既読管理: テーブル内の最大 id を session に記録して未読バッヂを消す。
    # inject_flags は「id > last_read_id」の件数を未読カウントとして返すため、
    # 最大 id を保存することで全件既読になる。
    if ann_list:
        max_id_row = get_db().execute("SELECT MAX(id) FROM bank_announcements").fetchone()
        session["bank_last_read_ann_id"] = max_id_row[0] if max_id_row and max_id_row[0] else 0
    return render_template("bank/announcements.html", user=user, announcements=ann_list)


# ---------------------------------------------------------------------------
# お知らせ管理（staff/admin 向け）— VulnBank トップの「お知らせ」を更新する。
#   利用者(role=user)は閲覧のみ。staff/admin だけが追加・編集・削除できる。
# ---------------------------------------------------------------------------

@app.route("/admin/announcements")
def announcements_admin():
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    if user["role"] not in ("staff", "admin"):
        abort(403)
    db = get_db()
    announcements = db.execute(
        "SELECT * FROM bank_announcements ORDER BY published_at DESC, id DESC"
    ).fetchall()
    db.close()
    return render_template("bank/announcements_admin.html", user=user,
                           announcements=announcements)


@app.route("/admin/announcements/new", methods=["POST"])
def announcements_new():
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    if user["role"] not in ("staff", "admin"):
        abort(403)
    title = request.form.get("title", "").strip()
    body = request.form.get("body", "").strip()
    published_at = request.form.get("published_at", "").strip() \
        or datetime.now(timezone(timedelta(hours=9))).strftime("%Y-%m-%d")
    if title:
        db = get_db()
        db.execute(
            "INSERT INTO bank_announcements (title, body, published_at) VALUES (?,?,?)",
            (title, body, published_at),
        )
        db.commit()
        db.close()
    return redirect(url_for("announcements_admin"))


@app.route("/admin/announcements/<int:ann_id>/edit", methods=["POST"])
def announcements_edit(ann_id):
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    if user["role"] not in ("staff", "admin"):
        abort(403)
    title = request.form.get("title", "").strip()
    body = request.form.get("body", "").strip()
    published_at = request.form.get("published_at", "").strip()
    if title:
        db = get_db()
        db.execute(
            "UPDATE bank_announcements SET title=?, body=?, published_at=? WHERE id=?",
            (title, body, published_at, ann_id),
        )
        db.commit()
        db.close()
    return redirect(url_for("announcements_admin"))


@app.route("/admin/announcements/<int:ann_id>/delete", methods=["POST"])
def announcements_delete(ann_id):
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    if user["role"] not in ("staff", "admin"):
        abort(403)
    db = get_db()
    db.execute("DELETE FROM bank_announcements WHERE id=?", (ann_id,))
    db.commit()
    db.close()
    return redirect(url_for("announcements_admin"))


@sock.route("/support/ws")
def support_ws(ws):
    """サポートチャットの WebSocket。意図的脆弱性を集中させる。"""
    # [VULN WS-1] Origin を一切検証しない（CSWSH）。認証は Cookie セッションのみ。
    user = current_user()
    # [VULN WS-3] ?room=<id> の所有者確認をしない。任意ルームに参加・履歴取得できる。
    room = request.args.get("room") or support_room_for(user)

    db = get_db()
    for row in support_history(db, room):
        ws.send(_support_msg(room, row["sender_name"], row["body"], row["created_at"]))
    db.close()

    clients = _support_clients.setdefault(room, set())
    clients.add(ws)
    sender_name = support_display_name(user)
    sender_id = user["id"] if user else None
    try:
        while True:
            data = ws.receive()
            if data is None:
                break
            try:
                msg = json.loads(data) or {}
                body = msg.get("body", "")
            except (ValueError, TypeError):
                msg = {}
                body = str(data)
            if not body:
                continue
            # [VULN WS-4] クライアントが送る sender を検証せず信用する（送信者なりすまし）。
            #   認証済みセッションの username を使わないため、利用者が "サポート窓口" や
            #   管理者を詐称してフィッシング（暗証番号の聞き出し等）を行える（CWE-290/345）。
            effective_sender = msg.get("sender") or sender_name
            db = get_db()
            support_save(db, room, sender_id, effective_sender, body)
            db.close()
            # [VULN WS-2] 受信本文を無加工のまま送信者を含む全接続へ配信する。
            #   受信側クライアントが innerHTML で描画するため格納 XSS になる。
            out = _support_msg(room, effective_sender, body)
            for c in list(clients):
                try:
                    c.send(out)
                except Exception:
                    clients.discard(c)
    finally:
        clients.discard(ws)


# ---------------------------------------------------------------------------
# Shop — Business Logic (price manipulation via hidden field, coupon abuse)
# ---------------------------------------------------------------------------

def get_products():
    """カタログ商品を DB から取得する（店舗担当者/管理者が編集できる）。"""
    db = get_db()
    rows = db.execute("SELECT * FROM products ORDER BY id").fetchall()
    db.close()
    return rows


def get_product(product_id):
    """単一商品を取得する（存在しなければ None）。"""
    db = get_db()
    row = db.execute("SELECT * FROM products WHERE id=?", (product_id,)).fetchone()
    db.close()
    return row


# 既知 SKU の販促コピー。商品詳細ページのチラ見せ用（DB の description とは別の装飾情報）。
# 管理者が追加した商品はここに無いので、汎用フォールバックを使う。
CATALOG_HIGHLIGHTS = {
    "Basic Account Upgrade": {
        "tagline": "毎日のお買い物が、ちょっと便利になる入門プラン。",
        "category": "メンバーシップ",
        "features": [
            "ストア内の広告を非表示",
            "注文履歴を 24 か月間保存",
            "お気に入り登録数を無制限に開放",
            "平日 9-18 時のメールサポート",
        ],
    },
    "Premium Membership": {
        "tagline": "送料無料 × お急ぎ便 × 先行セール。人気 No.1 プラン。",
        "category": "メンバーシップ",
        "features": [
            "全国どこでも送料無料",
            "お急ぎ便が使い放題",
            "会員限定セールに先行アクセス",
            "ポイント常時 2 倍",
            "チャットサポート対応",
        ],
    },
    "VIP Gold Card": {
        "tagline": "VulnEC 最上位ステータス。特別な体験をひとまとめに。",
        "category": "プレミアム",
        "features": [
            "専任コンシェルジュが対応",
            "ポイント還元 最大 10%",
            "新商品の優先購入枠",
            "誕生月クーポンを毎年プレゼント",
            "24 時間 365 日の優先サポート",
        ],
    },
}

def get_product_reviews(product_id):
    """商品に投稿された購入者レビューを新しい順に取得する。"""
    db = get_db()
    rows = db.execute(
        "SELECT * FROM reviews WHERE product_id=? ORDER BY created_at DESC, id DESC",
        (product_id,),
    ).fetchall()
    db.close()
    return rows


def product_presentation(product, user_reviews=None):
    """商品の「見せ方」情報（評価・在庫・SKU・特徴・レビュー）を組み立てる。

    DB スキーマ（name/price/description）を変えずに、商品ページらしい付帯情報を
    id から決定論的に生成する。レビューは実際に投稿されたものだけを表示し、
    未投稿の商品は空状態（評価なし）として返す（サンプルの作り物は出さない）。
    """
    pid = product["id"]
    highlight = CATALOG_HIGHLIGHTS.get(product["name"], {})
    stock = 3 + (pid * 17) % 46

    reviews = [{"id": r["id"], "name": r["author"], "stars": r["rating"] or 5,
                "body": r["body"], "date": r["created_at"]} for r in (user_reviews or [])]
    ratings = [r["stars"] for r in reviews if r["stars"]]
    rating = round(sum(ratings) / len(ratings), 1) if ratings else None
    rating_count = len(reviews)

    return {
        "sku": "VEC-%04d" % pid,
        "category": highlight.get("category", "一般"),
        "tagline": highlight.get("tagline", "VulnEC が厳選してお届けする一品です。"),
        "features": highlight.get("features", [
            "安心の VulnEC 品質保証",
            "購入後すぐに利用可能",
            "いつでもオンラインで管理",
        ]),
        "rating": rating,
        "rating_count": rating_count,
        "stock": stock,
        "reviews": reviews,
        "has_real_reviews": bool(reviews),
    }


@app.route("/shop")
def shop():
    user = current_user()
    products = get_products()
    # カテゴリ情報を商品ごとに取得（product_presentation から category を抽出）
    cat_by_id = {}
    for p in products:
        pres = product_presentation(p)
        cat_by_id[p["id"]] = pres["category"]
    # 重複除去しつつ出現順を維持したカテゴリリスト
    seen = set()
    categories = []
    for p in products:
        c = cat_by_id[p["id"]]
        if c not in seen:
            seen.add(c)
            categories.append(c)
    # 利用可能クーポンの掲示（コード・割引・残り回数）。店舗の通常コンテンツとして
    # 常時表示する（nohint でも隠さない）。BIZ-3 のレース自体の解説は別途
    # チェックアウト画面の vuln_hint（nohint で非表示）に置く。
    db = get_db()
    coupons = db.execute(
        "SELECT code, discount, max_uses, used_count FROM coupons ORDER BY discount DESC"
    ).fetchall()
    db.close()
    return render_template("ec/shop.html", user=user, products=products,
                           cat_by_id=cat_by_id, categories=categories, coupons=coupons)


@app.route("/shop/product/<int:product_id>")
def shop_product(product_id):
    """商品詳細ページ（現実の EC と同じく商品ごとの専用ページ）。"""
    product = get_product(product_id)
    if not product:
        abort(404)
    user = current_user()
    reviews = get_product_reviews(product_id)
    related = [p for p in get_products() if p["id"] != product_id][:4]
    return render_template("ec/product_detail.html", user=user, product=product,
                           meta=product_presentation(product, reviews),
                           related=related)


def _deny_shop_for_staff(user):
    """admin/staff（運営アカウント）は顧客向けの購買機能を使わない。

    ショップ購入・カート・チェックアウト・マイページ・購入履歴は顧客(user)専用とし、
    運営アカウントは管理コンソールのみに寄せる（本物の EC らしさ）。
    顧客(user)経路は一切変えないため、意図的脆弱性
    （IDOR-2 / XSS-S3 / BIZ-2 / BIZ-3 等）はそのまま温存される。
    """
    if user and user["role"] in ("staff", "admin"):
        abort(403)


@app.route("/shop/product/<int:product_id>/checkout")
def checkout(product_id):
    """商品購入画面。数量・クーポン・支払い方法（代引き / ポイント利用）を選んで注文する。"""
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    _deny_shop_for_staff(user)
    product = get_product(product_id)
    if not product:
        abort(404)
    quantity = request.args.get("quantity", type=int, default=1) or 1
    return render_template("ec/checkout.html", user=user, product=product,
                           quantity=max(1, quantity))


# ---------------------------------------------------------------------------
# カート（複数商品）＋多段チェックアウト（カート→住所→支払い→確認→購入）。
#   リアルな EC 体験のための導線。脆弱性は増やさない（最終確定は従来どおり
#   /shop/buy に POST し、各行の price を hidden で送るため BIZ-2 はそのまま）。
#   カートは署名 Cookie セッション上に保持する（未ログインでも追加・閲覧可）。
# ---------------------------------------------------------------------------

def _get_cart():
    """セッション上のカート（[{product_id, qty}, ...]）を返す。"""
    return session.get("cart", [])


def _save_cart(cart):
    session["cart"] = cart
    session.modified = True


def _cart_lines(cart):
    """カート各行に商品情報を結合した表示用リストと小計を返す（存在しない商品は除外）。"""
    lines = []
    subtotal = 0.0
    for item in cart:
        product = get_product(item.get("product_id"))
        if not product:
            continue
        qty = max(1, int(item.get("qty", 1) or 1))
        line_total = product["price"] * qty
        subtotal += line_total
        lines.append({"product": product, "qty": qty, "line_total": line_total})
    return lines, subtotal


@app.route("/cart/add", methods=["POST"])
def cart_add():
    """商品をカートに追加する（未ログインでも可）。同一商品は数量を加算。"""
    _deny_shop_for_staff(current_user())
    product_id = request.form.get("product_id", type=int)
    quantity = max(1, request.form.get("quantity", type=int, default=1) or 1)
    if not product_id or not get_product(product_id):
        abort(404)
    cart = _get_cart()
    for item in cart:
        if item.get("product_id") == product_id:
            item["qty"] = int(item.get("qty", 0)) + quantity
            break
    else:
        cart.append({"product_id": product_id, "qty": quantity})
    _save_cart(cart)
    return redirect(url_for("cart_view"))


@app.route("/cart")
def cart_view():
    """カート明細。"""
    user = current_user()
    _deny_shop_for_staff(user)
    lines, subtotal = _cart_lines(_get_cart())
    return render_template("ec/cart.html", user=user, lines=lines, subtotal=subtotal)


@app.route("/cart/update", methods=["POST"])
def cart_update():
    """数量変更・行削除。remove=1 もしくは qty<=0 で削除する。"""
    _deny_shop_for_staff(current_user())
    product_id = request.form.get("product_id", type=int)
    qty = request.form.get("qty", type=int, default=1)
    remove = request.form.get("remove")
    new_cart = []
    for item in _get_cart():
        if item.get("product_id") == product_id:
            if remove or qty is None or qty <= 0:
                continue  # 削除
            item["qty"] = qty
        new_cart.append(item)
    _save_cart(new_cart)
    return redirect(url_for("cart_view"))


# 配送方法定数: key → (表示名, 追加送料)
# 送料は表示のみ。会計（ポイント残高の増減）には含めない。
SHIPPING_METHODS = {
    "standard": ("通常配送", 0),
    "express": ("お急ぎ便", 500),
}


def _shipping_fee(method):
    """配送方法の送料（円）を返す。不正値は 0（通常配送と同じ）。"""
    return SHIPPING_METHODS.get(method, SHIPPING_METHODS["standard"])[1]


@app.route("/checkout/shipping", methods=["GET", "POST"])
def checkout_shipping():
    """① 配送先（お届け先）入力。ログイン必須・カート必須。"""
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    _deny_shop_for_staff(user)
    lines, subtotal = _cart_lines(_get_cart())
    if not lines:
        return redirect(url_for("cart_view"))
    if request.method == "POST":
        # 住所は単一カラム維持のため「都道府県市区町村（自動入力）＋番地・建物（手入力）」を連結する。
        region = request.form.get("ship_region", "").strip()
        rest = request.form.get("ship_rest", "").strip()
        ship_method = request.form.get("ship_method", "standard")
        if ship_method not in SHIPPING_METHODS:
            ship_method = "standard"
        session["checkout_ship"] = {
            "ship_name": request.form.get("ship_name", "").strip(),
            "ship_postal": request.form.get("ship_postal", "").strip(),
            "ship_region": region,
            "ship_rest": rest,
            "ship_address": (region + " " + rest).strip(),
            "ship_phone": request.form.get("ship_phone", "").strip(),
            "ship_method": ship_method,
        }
        session.modified = True
        return redirect(url_for("checkout_payment"))
    return render_template("ec/checkout_shipping.html", user=user, lines=lines,
                           subtotal=subtotal, saved=session.get("checkout_ship", {}),
                           shipping_methods=SHIPPING_METHODS)


def _validate_coupon_for_display(code):
    """クーポンの「表示用」検証。使用回数は消費しない。

    ここでは在庫(used_count)を更新しないため、利用回数の check-then-act 競合（BIZ-3）は
    最終確定の /shop/buy 側にそのまま温存される（意図的脆弱性は不変）。
    戻り値: (discount: float, message: str|None, ok: bool|None)
    """
    if not code:
        return 0.0, None, None
    db = get_db()
    row = db.execute("SELECT * FROM coupons WHERE code=?", (code,)).fetchone()
    db.close()
    if not row:
        return 0.0, "クーポンコード「%s」は無効です。" % code, False
    if row["used_count"] >= row["max_uses"]:
        return 0.0, "クーポン「%s」は利用上限に達しています。" % code, False
    return row["discount"], "クーポン「%s」を適用しました（%d%%OFF）。" % (code, round(row["discount"] * 100)), True


@app.route("/checkout/payment", methods=["GET", "POST"])
def checkout_payment():
    """② お支払い方法・クーポン選択。ログイン・カート・住所入力済みが必須。"""
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    _deny_shop_for_staff(user)
    lines, subtotal = _cart_lines(_get_cart())
    if not lines:
        return redirect(url_for("cart_view"))
    if "checkout_ship" not in session:
        return redirect(url_for("checkout_shipping"))
    if request.method == "POST":
        action = request.form.get("action", "proceed")
        payment_method = request.form.get("payment_method", "cod")
        if payment_method not in ("points", "cod", "combo"):
            payment_method = "cod"
        coupon_code = request.form.get("coupon", "").strip().upper()
        # 「確定」/「確認画面へ進む」いずれでもクーポンを表示用に検証する（使用は消費しない）。
        coupon_discount, coupon_msg, coupon_ok = _validate_coupon_for_display(coupon_code)
        session["checkout_pay"] = {
            "payment_method": payment_method,
            "points_used": request.form.get("points_used", type=float, default=0) or 0.0,
            "coupon": coupon_code,
            "coupon_discount": coupon_discount,
        }
        session.modified = True
        if action == "apply_coupon":
            # クーポン「確定」: このページに留まり、適用結果と割引後の金額を表示する。
            return render_template("ec/checkout_payment.html", user=user, lines=lines,
                                   subtotal=subtotal, saved=session["checkout_pay"],
                                   coupon_msg=coupon_msg, coupon_ok=coupon_ok)
        return redirect(url_for("checkout_confirm"))
    return render_template("ec/checkout_payment.html", user=user, lines=lines,
                           subtotal=subtotal, saved=session.get("checkout_pay", {}))


@app.route("/checkout/confirm")
def checkout_confirm():
    """③ 注文内容の確認。最終フォームは /shop/buy に POST（各行の price を hidden で出力）。"""
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    _deny_shop_for_staff(user)
    lines, subtotal = _cart_lines(_get_cart())
    if not lines:
        return redirect(url_for("cart_view"))
    ship = session.get("checkout_ship")
    pay = session.get("checkout_pay")
    if not ship:
        return redirect(url_for("checkout_shipping"))
    if not pay:
        return redirect(url_for("checkout_payment"))
    # 配送方法に対応する送料を計算（表示のみ・会計には使わない）。
    ship_method = ship.get("ship_method", "standard")
    shipping_fee = _shipping_fee(ship_method)
    # 確定済みクーポンの割引（表示用）。coupon_discount は payment 画面で検証済みの割引率。
    discount = float(pay.get("coupon_discount") or 0.0)
    discount_amount = subtotal * discount
    grand_total = subtotal - discount_amount + shipping_fee
    return render_template("ec/checkout_confirm.html", user=user, lines=lines,
                           subtotal=subtotal, ship=ship, pay=pay,
                           shipping_fee=shipping_fee, grand_total=grand_total,
                           discount=discount, discount_amount=discount_amount,
                           shipping_methods=SHIPPING_METHODS)


@app.route("/shop/buy", methods=["POST"])
def shop_buy():
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    _deny_shop_for_staff(user)

    # 単一商品（旧「今すぐ購入」/直接攻撃）でもカート確定（複数行）でも同じ口で受ける。
    # product_id / price / quantity は getlist で複数行に対応（単一行なら 1 要素）。
    product_ids = request.form.getlist("product_id")
    prices = request.form.getlist("price")
    quantities = request.form.getlist("quantity")
    from_cart = bool(request.form.get("from_cart"))

    coupon_code = request.form.get("coupon", "").strip().upper()
    # 支払い方法: points（全額ポイント）/ cod（代引き）/ combo（現金＋ポイント併用）。
    # 未指定はポイント利用。
    payment_method = request.form.get("payment_method", "points")
    if payment_method not in ("points", "cod", "combo"):
        payment_method = "points"
    # 配送先（お届け先）。購入画面で入力する。
    ship_name = request.form.get("ship_name", "").strip()
    ship_postal = request.form.get("ship_postal", "").strip()
    ship_address = request.form.get("ship_address", "").strip()
    ship_phone = request.form.get("ship_phone", "").strip()

    def _to_int(v, d=None):
        try:
            return int(v)
        except (TypeError, ValueError):
            return d

    def _to_float(v, d=0.0):
        try:
            return float(v)
        except (TypeError, ValueError):
            return d

    db = get_db()

    # 各行を (product, price, qty) に解決する。
    # [VULN-BizLogic] Price taken from form (per line) — client can tamper it（BIZ-2）。
    lines = []
    for idx, pid_raw in enumerate(product_ids):
        pid = _to_int(pid_raw)
        product = db.execute("SELECT * FROM products WHERE id=?", (pid,)).fetchone() if pid is not None else None
        if not product:
            if len(product_ids) <= 1:
                # 単一行（旧来の直接購入/攻撃）では従来どおり 404。
                db.close()
                return "Product not found", 404
            continue  # 複数行では存在しない行はスキップ
        price = _to_float(prices[idx]) if idx < len(prices) else 0.0
        qty = max(1, _to_int(quantities[idx], 1) if idx < len(quantities) else 1)
        lines.append({"product": product, "price": price, "qty": qty})

    if not lines:
        db.close()
        return "Product not found", 404

    def _checkout_error(msg):
        db.close()
        if from_cart or len(lines) > 1:
            # カート確定フローは確認画面にエラーを出してやり直させる。
            c_lines, c_subtotal = _cart_lines(_get_cart())
            return render_template("ec/checkout_confirm.html", user=user, lines=c_lines,
                                   subtotal=c_subtotal, ship=session.get("checkout_ship", {}),
                                   pay=session.get("checkout_pay", {}), error=msg)
        return render_template("ec/checkout.html", user=user, product=lines[0]["product"],
                               quantity=lines[0]["qty"], error=msg)

    discount = 0.0
    if coupon_code:
        # [VULN-BizLogic] Race condition on coupon — check-then-act not atomic
        coupon = db.execute(
            "SELECT * FROM coupons WHERE code=? AND used_count < max_uses", (coupon_code,)
        ).fetchone()
        if coupon:
            discount = coupon["discount"]
            db.execute("UPDATE coupons SET used_count = used_count + 1 WHERE code=?", (coupon_code,))
        else:
            return _checkout_error("クーポンコードが無効か、利用上限に達しています。")

    # Use the client-supplied prices (vulnerable), not product["price"]
    subtotal = sum(l["price"] * l["qty"] for l in lines)
    total = subtotal * (1 - discount)

    # 販売価格は円。ポイントは 1 pt = ¥1 として円建て金額に充当する。
    me = db.execute("SELECT * FROM ec_users WHERE id=?", (user["id"],)).fetchone()
    points_used = 0.0
    if payment_method == "points":
        # 全額ポイント: 残高が足りなければ購入できない。
        if me["balance"] < total:
            return _checkout_error("ポイントが不足しています。代引き、または現金との併用をご利用ください。")
        points_used = total
    elif payment_method == "combo":
        # 現金＋ポイント併用: 使うポイントは「残高」と「合計額」の小さい方が上限。
        # 不足分は代引き（お届け時に現金）で支払う。
        points_used = request.form.get("points_used", type=float, default=0) or 0.0
        points_used = max(0.0, min(points_used, total, me["balance"]))
    # cod は points_used=0（全額を代引きで支払う）

    if points_used:
        db.execute("UPDATE ec_users SET balance = balance - ? WHERE id=?", (points_used, user["id"]))
    cash_due = total - points_used

    # 表示名: 単一行は従来どおり「商品名」、複数行は「先頭商品名」ほかN点。
    first_name = lines[0]["product"]["name"]
    label = f"「{first_name}」" if len(lines) == 1 else f"「{first_name}」ほか{len(lines) - 1}点"
    if payment_method == "points":
        success = f"{label}を ¥{total:,.0f}（{points_used:,.0f} pt 利用）で購入しました。"
    elif payment_method == "combo":
        success = (f"{label}を ¥{total:,.0f}"
                   f"（{points_used:,.0f} pt 利用 ＋ 代引き ¥{cash_due:,.0f}）で購入しました。"
                   f"お届け時に ¥{cash_due:,.0f} をお支払いください。")
    else:
        success = (f"{label}を代引きで注文しました。"
                   f"お届け時に ¥{total:,.0f} をお支払いください。")

    # 各行を orders に 1 行ずつ INSERT（既存スキーマ＝1商品1行を維持）。
    # 行の total は割引適用後の小計。points_used は行へ比例配分し、合計が一致するよう
    # 端数は最終行へ寄せる（単一行なら従来どおり total / points_used がそのまま入る）。
    assigned_points = 0.0
    inserted_ids = []
    for i, l in enumerate(lines):
        line_total = l["price"] * l["qty"] * (1 - discount)
        l["line_total"] = line_total  # order_complete.html 用に各行へ付与
        if i == len(lines) - 1:
            line_points = points_used - assigned_points
        else:
            line_points = (points_used * (l["price"] * l["qty"]) / subtotal) if subtotal else 0.0
            assigned_points += line_points
        cur = db.execute(
            "INSERT INTO orders (user_id, product_id, item, quantity, price, total, coupon_used,"
            " payment_method, points_used, ship_name, ship_postal, ship_address, ship_phone)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (user["id"], l["product"]["id"], l["product"]["name"], l["qty"], l["price"], line_total,
             coupon_code or None, payment_method, line_points,
             ship_name, ship_postal, ship_address, ship_phone),
        )
        inserted_ids.append(cur.lastrowid)
    db.commit()
    db.close()

    # カート確定フローならセッションを掃除する（単一商品の直接購入では触らない）。
    if from_cart or len(lines) > 1:
        session.pop("cart", None)
        session.pop("checkout_ship", None)
        session.pop("checkout_pay", None)
        session.modified = True

    # 購入完了ページへ直接レンダリング（PRG しない）。
    # order_id は先頭注文の id（複数行でも代表 id として先頭を渡す）。
    order_id = inserted_ids[0] if inserted_ids else None
    complete_total = sum(l["line_total"] for l in lines)
    return render_template(
        "ec/order_complete.html",
        user=user,
        success=success,
        order_id=order_id,
        lines=lines,
        total=complete_total,
    )


# ---------------------------------------------------------------------------
# 商品管理（店舗担当者/管理者向け）— [VULN AUTHZ-2] 機能レベル認可の欠落（BFLA）
#   ナビは staff/admin にしかリンクを出さないが、サーバ側はロールを検証しないため
#   利用者(user)でも直接 URL を叩けば商品を作成/編集/削除できる（CWE-862）。
# ---------------------------------------------------------------------------

@app.route("/admin/products")
def products_admin():
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    # [VULN AUTHZ-2] ログイン要求のみ。staff/admin かのチェックが無い。
    return render_template("ec/products_admin.html", user=user, products=get_products())


@app.route("/admin/products/new", methods=["GET", "POST"])
def product_new():
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        price = request.form.get("price", type=float, default=0.0)
        description = request.form.get("description", "")
        # [VULN AUTHZ-2] ロール検証なしで誰でも商品を追加できる。
        db = get_db()
        db.execute("INSERT INTO products (name, price, description) VALUES (?,?,?)",
                   (name, price, description))
        db.commit()
        db.close()
        return redirect(url_for("products_admin"))
    return render_template("ec/product_form.html", user=user, product=None)


@app.route("/admin/products/<int:product_id>/edit", methods=["GET", "POST"])
def product_edit(product_id):
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    db = get_db()
    product = db.execute("SELECT * FROM products WHERE id=?", (product_id,)).fetchone()
    if not product:
        db.close()
        abort(404)
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        price = request.form.get("price", type=float, default=0.0)
        description = request.form.get("description", "")
        # [VULN AUTHZ-2] ロール検証なしで誰でも商品を改ざんできる。
        db.execute("UPDATE products SET name=?, price=?, description=? WHERE id=?",
                   (name, price, description, product_id))
        db.commit()
        db.close()
        return redirect(url_for("products_admin"))
    db.close()
    return render_template("ec/product_form.html", user=user, product=product)


@app.route("/admin/products/<int:product_id>/delete", methods=["POST"])
def product_delete(product_id):
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    # [VULN AUTHZ-2] ロール検証なしで誰でも商品を削除できる。
    db = get_db()
    db.execute("DELETE FROM products WHERE id=?", (product_id,))
    db.commit()
    db.close()
    return redirect(url_for("products_admin"))


# ---------------------------------------------------------------------------
# マイページ — EC 会員情報（読み取り専用）
# ---------------------------------------------------------------------------

def _member_rank(balance):
    """ポイント残高からシンプルな会員ランクを決定論的に返す。"""
    if balance >= 10000:
        return "ゴールド"
    if balance >= 5000:
        return "シルバー"
    return "一般"


@app.route("/mypage")
def mypage():
    """マイページ: ユーザー情報・ポイント残高・会員ランク（読み取り専用）。"""
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    _deny_shop_for_staff(user)
    rank = _member_rank(user["balance"])
    return render_template("ec/mypage.html", user=user, rank=rank)


# ---------------------------------------------------------------------------
# Orders — IDOR / 購入履歴・購入者レビュー
# ---------------------------------------------------------------------------

def _order_status(created_at: str) -> str:
    """経過日数から注文ステータスを決定論的に返す。

    Args:
        created_at: "YYYY-MM-DD HH:MM:SS" 形式の UTC 日時文字列

    Returns:
        "処理中" (0〜1日) / "発送済み" (2〜4日) / "完了" (5日以上)
        パース失敗時は "処理中" にフォールバック。
    """
    try:
        dt = datetime.strptime(created_at, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
        now = datetime.now(tz=timezone.utc)
        elapsed_days = (now - dt).days
    except Exception:
        return "処理中"

    if elapsed_days <= 1:
        return "処理中"
    elif elapsed_days <= 4:
        return "発送済み"
    else:
        return "完了"


@app.route("/orders")
def my_orders():
    """購入履歴。ここから購入済み商品にレビューを投稿できる。"""
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    _deny_shop_for_staff(user)
    db = get_db()
    orders = db.execute(
        "SELECT * FROM orders WHERE user_id=? ORDER BY created_at DESC, id DESC",
        (user["id"],),
    ).fetchall()
    # 注文ごとの投稿済みレビュー（order_id -> review）
    reviews_by_order = {
        r["order_id"]: r
        for r in db.execute("SELECT * FROM reviews WHERE user_id=?", (user["id"],)).fetchall()
    }
    db.close()
    # 注文ごとのステータス（order_id -> ステータス文字列）
    status_by_order = {o["id"]: _order_status(o["created_at"]) for o in orders}
    return render_template("ec/orders.html", user=user, orders=orders,
                           reviews_by_order=reviews_by_order,
                           status_by_order=status_by_order)


@app.route("/orders/<int:order_id>/review", methods=["POST"])
def order_review(order_id):
    """購入履歴から商品レビューを投稿する（自分の注文・1 注文 1 レビュー）。"""
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    _deny_shop_for_staff(user)
    db = get_db()
    order = db.execute("SELECT * FROM orders WHERE id=?", (order_id,)).fetchone()
    if not order:
        db.close()
        abort(404)
    # 購入履歴からのレビューなので、自分の注文に限る。
    if order["user_id"] != user["id"]:
        db.close()
        abort(403)
    # 既にレビュー済みなら二重投稿しない。
    if db.execute("SELECT id FROM reviews WHERE order_id=?", (order_id,)).fetchone():
        db.close()
        return redirect(url_for("my_orders"))

    rating = request.form.get("rating", type=int, default=5)
    rating = max(1, min(5, rating))
    # [VULN-StoredXSS XSS-S3] レビュー本文を無害化せずそのまま保存する。
    # 商品詳細ページ（ec/product_detail.html）が |safe で描画するため蓄積型 XSS になる。
    body = request.form.get("body", "").strip()
    if not body:
        db.close()
        return redirect(url_for("my_orders"))

    # 商品 ID は注文に保存済み。旧注文（NULL）は商品名から引き直す。
    product_id = order["product_id"]
    if not product_id:
        prow = db.execute("SELECT id FROM products WHERE name=?", (order["item"],)).fetchone()
        product_id = prow["id"] if prow else None

    db.execute(
        "INSERT INTO reviews (product_id, order_id, user_id, author, rating, body) VALUES (?,?,?,?,?,?)",
        (product_id, order_id, user["id"], user["username"], rating, body),
    )
    db.commit()
    db.close()
    if product_id:
        return redirect(url_for("shop_product", product_id=product_id))
    return redirect(url_for("my_orders"))


@app.route("/shop/reviews/<int:review_id>/delete", methods=["POST"])
def review_delete(review_id):
    """レビューの削除。店舗担当者(staff)・管理者(admin)のみ実行できる（モデレーション）。"""
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    # 機能レベル認可: 店舗担当者・管理者だけがレビューを削除できる。
    if user["role"] not in ("staff", "admin"):
        abort(403)
    db = get_db()
    review = db.execute("SELECT * FROM reviews WHERE id=?", (review_id,)).fetchone()
    if not review:
        db.close()
        abort(404)
    product_id = review["product_id"]
    db.execute("DELETE FROM reviews WHERE id=?", (review_id,))
    db.commit()
    db.close()
    if product_id:
        return redirect(url_for("shop_product", product_id=product_id))
    return redirect(url_for("shop"))


@app.route("/orders/<int:order_id>")
def order_detail(order_id):
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    _deny_shop_for_staff(user)
    db = get_db()
    # [VULN-IDOR] No ownership check
    order = db.execute("SELECT * FROM orders WHERE id=?", (order_id,)).fetchone()
    db.close()
    if not order:
        abort(404)
    return render_template("ec/order_detail.html", user=user, order=order)


# ---------------------------------------------------------------------------
# 商品マニュアル配布 — Path Traversal
#   購入前後に取扱説明書（マニュアル）をダウンロードできる店舗機能。
#   ダウンロードは file パラメータで指定したファイルを MANUALS_DIR から読むが、
#   封じ込めをしていないため PATH-1（パストラバーサル）が成立する。
# ---------------------------------------------------------------------------

@app.route("/shop/manual")
def manual_download():
    # 商品ページの「取扱説明書をダウンロード」リンク (/shop/manual?file=manual-N.txt) から
    # 利用する。file をサニタイズせず os.path.join するため PATH-1 が成立する（意図的）。
    user = current_user()
    filename = request.args.get("file", "")
    content = None
    error = None

    if filename:
        # [VULN-PathTraversal] No sanitization — allows ../../etc/passwd
        path = os.path.join(MANUALS_DIR, filename)
        try:
            with open(path, "r", errors="replace") as f:
                content = f.read()
        except Exception as e:
            error = str(e)

    return render_template("ec/manuals.html", user=user,
                           content=content, filename=filename, error=error)


# ---------------------------------------------------------------------------
# 商品画像のURL取り込み + サムネイル生成 — Command Injection
#   取得した画像をパイプで ImageMagick(convert) に渡してサムネイル化する。
#   パイプのため shell=True が必要になり、URL を無加工で連結しているので
#   URL 経由でコマンドインジェクションが成立する（CMD-1）。
# ---------------------------------------------------------------------------

@app.route("/admin/image-import", methods=["GET", "POST"])
def image_import():
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    output = None
    if request.method == "POST":
        image_url = request.form.get("image_url", "")
        os.makedirs(UPLOADS_DIR, exist_ok=True)
        dest = os.path.join(UPLOADS_DIR, "thumb.png")
        # [VULN-CmdInjection] 取得画像をパイプで convert に渡すため shell=True。
        # image_url を無加工で連結しており、URL 経由で任意コマンドを実行できる。
        cmd = f"curl -fsSL --max-time 10 {image_url} | convert - -resize 400x400 {dest}"
        try:
            result = subprocess.run(
                cmd, shell=True, capture_output=True, text=True, timeout=15
            )
            output = (result.stdout + result.stderr) or "（出力なし。サムネイルを生成しました）"
        except subprocess.TimeoutExpired:
            output = "Timeout."
        except Exception as e:
            output = str(e)
    return render_template("ec/image_import.html", user=user, output=output)


# ---------------------------------------------------------------------------
# Admin Panel — Broken Access Control
# ---------------------------------------------------------------------------

@app.route("/admin")
def admin():
    user = current_user()
    # [VULN-AuthZ] Authorization based only on URL param — bypass with ?admin=1
    if request.args.get("admin") == "1" or (user and user["role"] == "admin"):
        db = get_db()
        users = db.execute("SELECT * FROM ec_users").fetchall()
        orders = db.execute("SELECT * FROM orders ORDER BY created_at DESC").fetchall()
        db.close()
        return render_template("ec/admin.html", user=user, users=users, orders=orders)
    abort(403)


@app.route("/admin/delete-user/<int:user_id>", methods=["POST"])
def admin_delete_user(user_id):
    # [VULN-AuthZ] Same bypass applies
    user = current_user()
    if not (request.args.get("admin") == "1" or (user and user["role"] == "admin")):
        abort(403)
    db = get_db()
    db.execute("DELETE FROM ec_users WHERE id=?", (user_id,))
    db.commit()
    db.close()
    return redirect(url_for("admin") + "?admin=1")


# ---------------------------------------------------------------------------
# ユーザー管理（管理者向け）— [VULN AUTHZ-3] 垂直権限昇格 + role マスアサインメント
#   利用者・店舗担当者を管理する管理者専用画面のはずだが、サーバ側は admin ロールを
#   検証しない（ログイン要求のみ）。よって非管理者でも /admin/users/<id>/role を直接
#   叩いて任意ユーザー（自分）を admin へ昇格できる（CWE-269 / 862 / 915）。
# ---------------------------------------------------------------------------

@app.route("/admin/users")
def users_admin():
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    # [VULN AUTHZ-3] admin ロールの確認が無い（ログインさえしていれば閲覧可能）。
    # ユーザー管理は bank/ec 共通機能。現在ログイン中のサイトのユーザーテーブルを対象にする。
    db = get_db()
    users = db.execute(f"SELECT * FROM {_session_table()} ORDER BY id").fetchall()
    db.close()
    return render_template("ec/users_admin.html", user=user, users=users)


@app.route("/admin/users/<int:user_id>/role", methods=["POST"])
def users_admin_set_role(user_id):
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    # [VULN AUTHZ-3] admin の確認が無く、クライアント提供の role をそのまま反映する。
    # 非管理者が自分の id を指定して role=admin を送れば権限昇格できる。
    role = request.form.get("role", "user")
    db = get_db()
    db.execute(f"UPDATE {_session_table()} SET role=? WHERE id=?", (role, user_id))
    db.commit()
    db.close()
    return redirect(url_for("users_admin"))


# ---------------------------------------------------------------------------
# VulnBoard — JWT セッションのタスク管理 SPA + JSON API（site=board）
# JWT の脆弱性は jwtutil.py に集約。ここはそれを使う薄い API 層。
# ---------------------------------------------------------------------------

def _bearer_token():
    """Authorization: Bearer <token> からトークンを取り出す。無ければ None。"""
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        return auth[len("Bearer "):].strip()
    return None


def _api_login_credentials():
    data = request.get_json(silent=True) or {}
    username = data.get("username") or request.form.get("username", "")
    password = data.get("password") or request.form.get("password", "")
    return username, password


def _issue_token(user):
    # [VULN JWT-4] 機微情報（平文パスワード・秘密メモ）をペイロードに格納。
    # [VULN JWT-5] exp を発行しない（無期限トークン）。
    claims = {
        "sub": user["username"],
        "uid": user["id"],
        "role": user["role"],
        "email": user["email"],
        "password": user["password"],
        "secret_note": user["secret_note"],
        "iat": int(time.time()),
    }
    return jwtutil.encode(claims, alg="HS256")    # [VULN JWT-3] 弱い秘密鍵で署名


@app.route("/api/login", methods=["POST"])
def api_login():
    username, password = _api_login_credentials()
    db = get_db()
    user = db.execute(
        "SELECT * FROM board_users WHERE username = ? AND password = ?", (username, password)
    ).fetchone()
    db.close()
    if not user:
        return jsonify({"error": "invalid credentials"}), 401
    return jsonify({"token": _issue_token(user), "token_type": "Bearer"})


@app.route("/api/register", methods=["POST"])
def api_register():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or request.form.get("username", "")).strip()
    password = data.get("password") or request.form.get("password", "")
    if not username or not password:
        return jsonify({"error": "username and password required"}), 400
    db = get_db()
    existing = db.execute("SELECT id FROM board_users WHERE username = ?", (username,)).fetchone()
    if existing:
        db.close()
        # [VULN ENUM-1] 既存ユーザー名で固有のエラーを返し、アカウント列挙を許す。
        return jsonify({"error": "username '%s' is already taken" % username}), 409
    # [VULN PWPOLICY-1] パスワードの長さ・複雑性を検証しない（"1" でも登録できる）。
    # [VULN MASS-1] クライアント提供の role をそのまま採用する（mass assignment → 権限昇格）。
    role = data.get("role") or request.form.get("role") or "user"
    cur = db.execute(
        "INSERT INTO board_users (username, password, email, role) VALUES (?,?,?,?)",
        (username, password, data.get("email"), role),
    )
    db.commit()
    user = db.execute("SELECT * FROM board_users WHERE id = ?", (cur.lastrowid,)).fetchone()
    db.close()
    return jsonify({"token": _issue_token(user), "token_type": "Bearer", "role": user["role"]}), 201


@app.route("/api/password", methods=["POST"])
def api_password():
    token = _bearer_token()
    if not token:
        return jsonify({"error": "missing bearer token"}), 401
    claims = jwtutil.verify(token)
    if claims is None:
        return jsonify({"error": "invalid token"}), 401
    data = request.get_json(silent=True) or {}
    old_password = data.get("old_password", "")
    new_password = data.get("new_password", "")
    if not new_password:
        return jsonify({"error": "new_password required"}), 400
    db = get_db()
    user = db.execute("SELECT * FROM board_users WHERE id = ?", (claims.get("uid"),)).fetchone()
    if not user:
        db.close()
        return jsonify({"error": "user not found"}), 404
    # 現在のパスワード確認を必須にする（本人のみ変更可能・新たな脆弱性は増やさない）。
    if user["password"] != old_password:
        db.close()
        return jsonify({"error": "current password is incorrect"}), 403
    db.execute("UPDATE board_users SET password = ? WHERE id = ?", (new_password, claims.get("uid")))
    db.commit()
    db.close()
    return jsonify({"ok": True})


@app.route("/api/me")
def api_me():
    token = _bearer_token()
    if not token:
        return jsonify({"error": "missing bearer token"}), 401
    # [VULN JWT-1/3/6] verify() が alg=none・弱い秘密鍵・公開鍵 HMAC を受理する。
    claims = jwtutil.verify(token)
    if claims is None:
        return jsonify({"error": "invalid token"}), 401
    return jsonify({"authenticated_as": claims.get("sub"), "claims": claims})


@app.route("/api/admin")
def api_admin():
    token = _bearer_token()
    if not token:
        return jsonify({"error": "missing bearer token"}), 401
    claims = jwtutil.verify(token)
    if claims is None:
        return jsonify({"error": "invalid token"}), 401
    # 権限はトークンの role クレームだけで判定 → 偽造トークンで昇格できる。
    if claims.get("role") != "admin":
        return jsonify({"error": "admin role required"}), 403
    db = get_db()
    users = db.execute("SELECT id, username, password, email, role FROM board_users").fetchall()
    tasks = db.execute("SELECT id, user_id, title, status FROM tasks ORDER BY user_id, position").fetchall()
    db.close()
    return jsonify({
        # exploit 到達を検知するための一意カナリア（honeytoken）。
        # 管理 API が内部サービス資格情報まで巻き込んで返してしまう想定。
        "internal_api_key": "intapi_live_9f3c2a7e4b81d605",
        "users": [dict(u) for u in users],     # 平文パスワードを含む全ユーザー
        "tasks": [dict(t) for t in tasks],     # 全ユーザーのタスク
    })


def _task_dict(row):
    return {"id": row["id"], "title": row["title"], "status": row["status"], "position": row["position"],
            "created_at": row["created_at"]}


@app.route("/api/tasks", methods=["GET", "POST"])
def api_tasks():
    token = _bearer_token()
    if not token:
        return jsonify({"error": "missing bearer token"}), 401

    if request.method == "POST":
        # 作成は通常どおり verify() で本人を確認（書き込みは追加の脆弱性を増やさない）。
        claims = jwtutil.verify(token)
        if claims is None:
            return jsonify({"error": "invalid token"}), 401
        data = request.get_json(silent=True) or {}
        title = (data.get("title") or "").strip()
        status = data.get("status") if data.get("status") in ("todo", "doing", "done") else "todo"
        if not title:
            return jsonify({"error": "title required"}), 400
        db = get_db()
        cur = db.execute(
            "INSERT INTO tasks (user_id, title, status, position) VALUES (?,?,?,?)",
            (claims.get("uid"), title, status, 0),
        )
        db.commit()
        row = db.execute("SELECT * FROM tasks WHERE id = ?", (cur.lastrowid,)).fetchone()
        db.close()
        return jsonify({"task": _task_dict(row)}), 201

    # [VULN JWT-2] GET は署名を検証せずにクレームを信頼する。
    # uid を書き換えた（署名のない/壊れた）トークンで他人のタスクを読める。
    claims = jwtutil.decode_unverified(token)
    if not claims:
        return jsonify({"error": "malformed token"}), 401
    db = get_db()
    rows = db.execute(
        "SELECT * FROM tasks WHERE user_id = ? ORDER BY position", (claims.get("uid"),)
    ).fetchall()
    db.close()
    return jsonify({"uid": claims.get("uid"), "tasks": [_task_dict(r) for r in rows]})


@app.route("/api/tasks/<int:task_id>/move", methods=["POST"])
def api_task_move(task_id):
    token = _bearer_token()
    if not token:
        return jsonify({"error": "missing bearer token"}), 401
    claims = jwtutil.verify(token)
    if claims is None:
        return jsonify({"error": "invalid token"}), 401
    data = request.get_json(silent=True) or {}
    status = data.get("status")
    if status not in ("todo", "doing", "done"):
        return jsonify({"error": "invalid status"}), 400
    db = get_db()
    # 自分のタスクのみ移動できる（書き込みは追加の脆弱性を増やさない）。
    db.execute("UPDATE tasks SET status = ? WHERE id = ? AND user_id = ?",
               (status, task_id, claims.get("uid")))
    db.commit()
    db.close()
    return jsonify({"ok": True, "id": task_id, "status": status})


@app.route("/api/pubkey")
def api_pubkey():
    # [VULN JWT-6] 公開鍵を配布。攻撃者はこれを HMAC 鍵に使い HS256 でトークンを偽造できる。
    return jsonify({"alg": "RS256", "public_key": jwtutil.RSA_PUBLIC_PEM})


# ---------------------------------------------------------------------------
# VulnGraph — 脆弱な GraphQL API（site=graphql）
# スキーマ/resolver は core/graphql_api.py（本物の ariadne）。ここは薄い HTTP 層。
# ---------------------------------------------------------------------------

def _graphql_execute(data):
    """単一オペレーションを実行して結果 dict と HTTP ステータスを返す。"""
    from ariadne import graphql_sync
    from core.graphql_api import schema
    # [VULN GQL-1] introspection=True のまま（スキーマ全開示）。debug=True で詳細エラーも返す。
    success, result = graphql_sync(schema, data or {}, introspection=True, debug=True)
    return result, (200 if success else 400)


@app.route("/graphql", methods=["GET", "POST"])
def graphql_server():
    if request.method == "GET":
        q = request.args.get("query")
        if q:
            # [VULN GQL-7] GET でクエリ/ミューテーションを受理する（CSRF: 状態変更が GET で起きる）。
            data = {"query": q}
            if request.args.get("operationName"):
                data["operationName"] = request.args.get("operationName")
            if request.args.get("variables"):
                try:
                    data["variables"] = json.loads(request.args.get("variables"))
                except ValueError:
                    pass
            result, status = _graphql_execute(data)
            return jsonify(result), status
        # [VULN GQL-2] 本番で GraphiQL エクスプローラを公開する（イントロスペクションUI露出）。
        from ariadne.explorer import ExplorerGraphiQL
        return ExplorerGraphiQL().html(request) or "", 200

    data = request.get_json(silent=True)
    if isinstance(data, list):
        # [VULN GQL-6] バッチ（複数オペレーションの配列）を無制限に受理する（DoS・総当りの増幅面）。
        return jsonify([_graphql_execute(op)[0] for op in data])
    result, status = _graphql_execute(data)
    return jsonify(result), status


# ---------------------------------------------------------------------------
# Vulnerability Map (for scanner operator reference)
# ---------------------------------------------------------------------------

# [設定] vuln-map を非表示にするオプション（= ヒント非表示モード）。
# HIDE_VULN_MAP=1 (または true/yes) で以下をまとめて隠す:
#   - /vuln-map エンドポイント (404) とナビのリンク
#   - 各ページに散らばる「脆弱性のヒント」(ペイロード例・解説文・誘導プレースホルダ等)
# 脆弱性そのもの(挙動)は隠さない。あくまで攻撃の手がかりだけを伏せる。
HIDE_VULN_MAP = os.environ.get("HIDE_VULN_MAP", "").strip().lower() in ("1", "true", "yes", "on")


@app.context_processor
def inject_flags():
    # テンプレートから参照できるようにフラグを注入。
    # nohint は hide_vuln_map の別名（ヒント全般の出し分けに使う）。
    # vuln_count は VULN_MAP の件数（ナビのバッジ等で表示。ハードコードを避ける）。
    feats = app.config.get("VULN_FEATURES", set())
    site = current_site()
    vulns = site_vulns()

    # bank 限定: お知らせ未読件数。
    # session["bank_last_read_ann_id"] より id が大きい件数を未読とみなす。
    # /announcements 訪問時に最新 id を記録するため、既読後はバッヂが消える。
    bank_unread_count = 0
    if site in ("all", "bank"):
        try:
            db = get_db()
            last_read_id = session.get("bank_last_read_ann_id", 0)
            row = db.execute(
                "SELECT COUNT(*) FROM bank_announcements WHERE id > ?", (last_read_id,)
            ).fetchone()
            bank_unread_count = row[0] if row else 0
            db.close()
        except Exception:
            bank_unread_count = 0

    return {
        "hide_vuln_map": HIDE_VULN_MAP,
        "nohint": HIDE_VULN_MAP,
        "vuln_count": len(vulns),
        "site_mode": site,
        "site_label": site_label(),
        "show_bank_nav": site in ("all", "bank"),
        "show_ec_nav": site in ("all", "ec"),
        "features": feats,
        "hard_mode": bool(feats),
        "delivery_dev_inbox": app.config.get("VULN_DELIVERY") == "dev_inbox",
        "f_waf": "waf" in feats,
        "f_otp": "otp" in feats,
        "f_email": "email_verify" in feats,
        "f_csrf": "csrf" in feats,
        "f_ratelimit": "ratelimit" in feats,
        "f_totp": "totp" in feats,
        "f_honeypot": "honeypot" in feats,
        "bank_unread_count": bank_unread_count,
    }


@app.route("/vuln-map")
def vuln_map():
    if HIDE_VULN_MAP:
        abort(404)
    user = current_user()
    # 全サイト共通の base.html レイアウトで表示（VulnEC/VulnBank と統一）。
    return render_template("common/vuln_map.html", user=user, vulns=site_vulns(),
                           bypass_map=WAF_BYPASS, waf_blocklist=security_features.WAF_BLOCKLIST)


@app.route("/vuln-map.json")
def vuln_map_json():
    """機械可読な正解データ（自動採点の基準）。ヒント非表示時は 404。"""
    if HIDE_VULN_MAP:
        abort(404)
    return jsonify({
        "site": current_site(),
        "count": len(site_vulns()),
        "vulns": site_vulns(),
        "observable_ids": harness.OBSERVABLE_IDS,
        "not_observable": harness.NOT_OBSERVABLE,
    })


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    init_db()
    # ローカル実行時は 127.0.0.1、Docker 内では HOST=0.0.0.0 を指定
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "5000"))
    # 既定 HTTP。VULN_TLS=1 で HTTPS（自己署名・全アプリで共有する1枚を certs/ から）。
    # 本番公開はしない前提。HTTPS（VULN_TLS=1）は評価の現実性（Secure/HSTS/TLS 系の指摘）のため。
    from core import certmaker
    ssl_context = certmaker.ssl_context_from_env(os.environ)
    scheme = "https" if ssl_context else "http"
    print("%s listening on %s://%s:%d" % (app.config["VULN_SITE"], scheme, host, port))
    # debug=True は意図的に維持（Werkzeug デバッガ露出は評価対象）。ただしリローダーは
    # 無効化する: 子プロセス起動(control.py)下でさらに孫サーバを fork し、停止時に孤児化
    # してポートを掴む二重プロセス問題を起こすため（Flask 公式も本番相当では推奨）。
    # threaded=True: WebSocket（/support/ws）は接続ごとに長時間ブロックするため、
    # 並行接続と通常の HTTP リクエストを同時に捌けるようスレッドを有効化する。
    app.run(debug=True, use_reloader=False, host=host, port=port,
            ssl_context=ssl_context, threaded=True)

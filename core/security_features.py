"""
ハードモードのバリア群。

設計方針:
- 有効なバリアは「個別フィーチャーフラグ」の集合（current_app.config["VULN_FEATURES"]）
  をリクエスト時に参照して判定する。import 時に値を固定しないこと
  （テストでの差し替え、コントロールパネルからの起動オプションに対応するため）。
- ここに置くのは「脆弱性の手前に被せる門」だけ。脆弱性本体のロジックは app.py 側に
  温存し、分岐させない。各バリアは該当フラグが無効のとき必ず素通りさせる。
- メール/SMS コード等は既定では /dev/inbox から取得可能にし、必要に応じて SMTP 配送へ
  切り替えられるようにする。正規スキャナ・自動テストが多段フローを完走できるようにする。
"""

import secrets
import time
from functools import wraps

from flask import current_app, session

# 個別に ON/OFF できるバリア（コントロールパネルで選択する）
ALL_FEATURES = ["waf", "otp", "email_verify", "csrf", "ratelimit", "totp", "honeypot"]


def parse_features(env):
    """
    環境変数からフィーチャー集合を決める。
    優先: VULN_FEATURES（カンマ区切り。例 "waf,otp"）。
    後方互換: 未指定なら DIFFICULTY=hard → 全機能 / それ以外 → なし。
    """
    raw = env.get("VULN_FEATURES")
    if raw is not None:
        return {f.strip() for f in raw.split(",") if f.strip()}
    if env.get("DIFFICULTY", "easy").strip().lower() == "hard":
        return set(ALL_FEATURES)
    return set()


def enabled_features():
    """現在有効なフィーチャー集合を返す（リクエスト時に評価）。"""
    return current_app.config.get("VULN_FEATURES", set())


def feature(name):
    """指定バリアが有効か。無効なら各バリアは素通りさせる。"""
    return name in enabled_features()


def is_hard():
    """いずれかのバリアが有効か（HARD バッジ等の判定用）。"""
    return bool(enabled_features())


def new_token(nbytes=16):
    """メール認証等で使うランダムトークンを生成する。"""
    return secrets.token_urlsafe(nbytes)


def new_otp():
    """6桁のワンタイムコードを生成する（送金・2FA などの確認用）。"""
    return "%06d" % secrets.randbelow(1_000_000)


# ---------------------------------------------------------------------------
# CSRF トークン（csrf）
# ---------------------------------------------------------------------------

def get_csrf_token():
    """セッションごとの CSRF トークン。無ければ発行する。"""
    tok = session.get("csrf_token")
    if not tok:
        tok = secrets.token_urlsafe(16)
        session["csrf_token"] = tok
    return tok


def csrf_valid(form):
    """送信フォームの csrf_token がセッションのものと一致するか。"""
    expected = session.get("csrf_token")
    return bool(expected) and form.get("csrf_token") == expected


# ---------------------------------------------------------------------------
# ハニーポット（honeypot）
# ---------------------------------------------------------------------------
# 人間には見えない隠しフィールド。Bot が全項目を埋めると値が入り、検知できる。
HONEYPOT_FIELD = "contact_url"


def honeypot_triggered(form):
    return bool((form.get(HONEYPOT_FIELD) or "").strip())


# ---------------------------------------------------------------------------
# レート制限 / アカウントロック（ratelimit）
# ---------------------------------------------------------------------------
# ログイン失敗をユーザー名ごとに記録し、一定回数で一時ロックする（総当たり抑止）。
LOGIN_MAX_FAILURES = 5
LOGIN_WINDOW = 300          # 失敗をカウントする時間窓（秒）
_login_failures = {}        # username -> [失敗時刻...]


def _recent_failures(username):
    cutoff = time.time() - LOGIN_WINDOW
    fails = [t for t in _login_failures.get(username, []) if t > cutoff]
    _login_failures[username] = fails
    return fails


def login_locked(username):
    return len(_recent_failures(username)) >= LOGIN_MAX_FAILURES


def record_login_failure(username):
    _login_failures.setdefault(username, []).append(time.time())


def clear_login_failures(username):
    _login_failures.pop(username, None)


def reset_state():
    """プロセス内に持つ状態（ロックアウト等）をリセットする。テスト用。"""
    _login_failures.clear()


# ---------------------------------------------------------------------------
# WAF風 入力フィルタ
# ---------------------------------------------------------------------------
# 素朴なブラックリスト方式。実在の「不完全なWAF」を模しており、意図的に回避可能。
# 各パターンの回避例は app.py の WAF_BYPASS に対応づけてある。
#   <script        → <svg onload=...>（代替タグ/イベント）
#   onerror        → 同上
#   union select   → UNION/**/SELECT（インラインコメントで連結を分断）
#   '--            → ' OR '1'='1（コメントを使わない論理式）
#   or 1=1         → ' OR '1'='1（クォートで別パターン化）
#   ../            → /etc/passwd（絶対パス。os.path.join の仕様で封じ込めを無視）
#   ; id / &&      → | id（パイプ）や $(id)、改行 %0a
WAF_BLOCKLIST = [
    "<script",
    "onerror",
    "../",
    "union select",
    "'--",
    "or 1=1",
    "; id",
    "; cat",
    "; ls",
    "&&",
]


def waf_blocks(values):
    """
    WAF。渡された値のいずれかが素朴な攻撃パターンに一致したら True。
    waf フラグ無効時は常に False。判定は小文字化した部分一致のみ＝回避可能。
    """
    if not feature("waf"):
        return False
    for v in values:
        if not v:
            continue
        low = str(v).lower()
        for pat in WAF_BLOCKLIST:
            if pat in low:
                return True
    return False


__all__ = [
    "ALL_FEATURES", "parse_features", "enabled_features", "feature", "is_hard",
    "new_token", "new_otp", "WAF_BLOCKLIST", "waf_blocks", "wraps",
    "get_csrf_token", "csrf_valid", "HONEYPOT_FIELD", "honeypot_triggered",
    "login_locked", "record_login_failure", "clear_login_failures", "reset_state",
]

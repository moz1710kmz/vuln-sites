"""
評価ハーネス: 攻撃シグネチャと自動採点。

検証アプリは全リクエストを request_log に記録する際、ここの classify() で
「そのリクエストがどの脆弱性を狙った形か」をタグ付けする（vuln ID の集合）。
パネルはそのタグを集計し、サーバ側で観測可能な脆弱性のうち何件に攻撃が
届いたか（到達カバレッジ）を採点する。

注意: これは「スキャナが攻撃ペイロードを送ったか（到達/網羅性）」を測る指標であり、
スキャナのレポート内容そのものではない。サーバ側で観測できない脆弱性
（DOM XSS / CSRF / クーポン競合 / 認証情報の保存方法など）は N/A とする。
"""

import re

from core.vulndata import VULN_MAP

# 攻撃ペイロードを示す素朴なパターン
_SQLI = re.compile(r"('|--|\bunion\b|\bor\b\s|\bselect\b|sleep\(|/\*)", re.I)
_XSS = re.compile(r"(<script|<svg|<img|onerror=|onload=|javascript:|%3cscript)", re.I)
_CMD = re.compile(r"(;|\||\$\(|`|&&|\bcat\b|\bid\b|%0a|\n)", re.I)
_TRAVERSAL = re.compile(r"(\.\./|\.\.\\|/etc/|/app/|\bpasswd\b|%2e%2e)", re.I)

# サーバ側で観測可能な脆弱性の判定（path, params -> bool）。
# キーが VULN_MAP の id。ここに無い id は「観測不可(N/A)」。
def _num(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


SIGNATURES = {
    "SQLi-1": lambda m, p, q: p == "/login" and m == "POST"
        and bool(_SQLI.search(q.get("username", "") + " " + q.get("password", ""))),
    "SQLi-2": lambda m, p, q: p == "/blog/search" and bool(_SQLI.search(q.get("q", ""))),
    "XSS-R":  lambda m, p, q: p == "/blog/search" and bool(_XSS.search(q.get("q", ""))),
    "XSS-S":  lambda m, p, q: bool(re.match(r"^/blog/\d+/comment$", p))
        and bool(_XSS.search(q.get("body", ""))),
    "XSS-S2": lambda m, p, q: p == "/blog/new"
        and bool(_XSS.search(q.get("title", "") + " " + q.get("body", ""))),
    "XSS-S3": lambda m, p, q: bool(re.match(r"^/orders/\d+/review$", p))
        and bool(_XSS.search(q.get("body", ""))),
    "IDOR-1": lambda m, p, q: bool(re.match(r"^/profile/\d+$", p)),
    "IDOR-2": lambda m, p, q: bool(re.match(r"^/orders/\d+$", p)),
    "PATH-1": lambda m, p, q: p == "/shop/manual" and bool(_TRAVERSAL.search(q.get("file", ""))),
    "CMD-1":  lambda m, p, q: p == "/admin/image-import" and bool(_CMD.search(q.get("image_url", ""))),
    # AUTHZ-1 は /admin 直下（と delete-user）に限定し、AUTHZ-2/3 の新パスを飲み込まない。
    "AUTHZ-1": lambda m, p, q: p == "/admin" or p.startswith("/admin/delete-user"),
    "AUTHZ-2": lambda m, p, q: p.startswith("/admin/products"),
    "AUTHZ-3": lambda m, p, q: p.startswith("/admin/users"),
    "AUTHZ-4": lambda m, p, q: bool(re.match(r"^/blog/\d+/(edit|delete)$", p)),
    "BIZ-1":  lambda m, p, q: p == "/transfer" and (_num(q.get("amount")) is not None
        and _num(q.get("amount")) < 0),
    "BIZ-2":  lambda m, p, q: p == "/shop/buy" and (_num(q.get("price")) is not None
        and _num(q.get("price")) < 2000),  # 最安商品(2000)未満の価格＝改ざんの疑い
    # WS-3: WebSocket ハンドシェイク GET /support/ws?room=... はパス/クエリに room が
    # 出るためログから観測可能（IDOR-1 と同様、所有者の判別はしないが「ルーム参照を
    # 試みた」形を採点する）。WS-1/2/4 はヘッダ/フレーム/スキーム起因で観測不可。
    "WS-3":   lambda m, p, q: p == "/support/ws" and bool(q.get("room")),
    # ENUM-2: 未認証で GET /transfer/lookup?account=<数値> を叩く＝口座番号→名義人の列挙。
    # パスとクエリパラメータから観測可能。
    "ENUM-2": lambda m, p, q: p == "/transfer/lookup" and bool(q.get("account")),
}

# サーバ側では観測できない脆弱性（採点の分母から除外する）
NOT_OBSERVABLE = {
    "XSS-D":  "DOM-based: ペイロードは URL フラグメントに置かれサーバへ届かない",
    "CSRF-1": "CSRF: トークン欠如はリクエスト単体からは判定不可",
    "CSRF-2": "CSRF: 同上",
    "BIZ-3":  "クーポン競合: 並行性に依存し単発リクエストでは判定不可",
    "AUTH-1": "平文保存: DB 実装の問題でリクエストからは観測不可",
    "AUTH-2": "弱い鍵: サーバ実装の問題",
    "AUTH-3": "セッション固定化: 単発リクエストからは判定不可",
    "COOKIE-1": "Cookie 属性(HttpOnly)欠如: レスポンスの Set-Cookie 検査が必要で、リクエストのパス/パラメータからは観測不可",
    "COOKIE-2": "Cookie 属性(Secure)欠如: 同上（Set-Cookie ヘッダの検査が必要）",
    "JWT-1":  "JWT alg=none: 攻撃は Authorization ヘッダ内で、パス/パラメータのログからは観測不可",
    "JWT-2":  "JWT 署名未検証: 同上（ヘッダ内のトークン改ざん）",
    "JWT-3":  "JWT 弱い署名鍵: 偽造はヘッダ内のため観測不可",
    "JWT-4":  "JWT 機微情報格納: トークン内容の問題でリクエストからは観測不可",
    "JWT-5":  "JWT 無期限: トークン内容(exp欠如)の問題で観測不可",
    "JWT-6":  "JWT alg 混同: 偽造はヘッダ内のため観測不可",
    "JWT-7":  "SPA の DOM/反射 XSS によるトークン窃取: board サイトはログ採点の対象外",
    "MASS-1": "登録時の mass assignment: JSON ボディの role はパス/パラメータのログに出ない",
    "ENUM-1": "アカウント列挙: 応答差分に依存し単発リクエストの分類では判定不可",
    "PWPOLICY-1": "弱いパスワードポリシー: ポリシー不在は実装の問題で観測不可",
    "GQL-1": "GraphQL イントロスペクション: 攻撃は POST /graphql のクエリ本文で、パス/パラメータのログからは観測不可",
    "GQL-2": "GraphiQL 公開: GET /graphql のUI露出はレスポンス内容の検査が必要で観測不可",
    "GQL-3": "GraphQL BOLA: クエリ本文(user(id))の問題で、パス/パラメータのログからは観測不可",
    "GQL-4": "GraphQL BFLA: ミューテーション本文(updateUser)の問題で観測不可",
    "GQL-5": "GraphQL 引数SQLi: ペイロードはクエリ本文の引数内にあり観測不可",
    "GQL-6": "GraphQL 深さ/バッチ制限なし: クエリ構造/バッチ配列の問題で観測不可",
    "GQL-7": "GraphQL CSRF: GET 受理の問題でレスポンス挙動の検査が必要",
    "WS-1":  "CSWSH: Origin 検証の欠如はハンドシェイクの Origin ヘッダ起因で、パス/パラメータのログからは観測不可",
    "WS-2":  "WebSocket 経由の格納 XSS: ペイロードは WS フレーム本文にあり、HTTP リクエストのパス/パラメータには出ない",
    "WS-4":  "送信者なりすまし: WS メッセージ本文(sender)の信用の問題で、リクエストのパス/パラメータからは観測不可",
}

OBSERVABLE_IDS = list(SIGNATURES.keys())


def classify(method, path, params):
    """リクエストが狙っている脆弱性 ID のリストを返す（0件もありうる）。"""
    out = []
    for vid, pred in SIGNATURES.items():
        try:
            if pred(method, path, params):
                out.append(vid)
        except Exception:
            pass
    return out


def _type_of(vid):
    for v in VULN_MAP:
        if v["id"] == vid:
            return v["type"]
    return "?"


def score(covered_ids):
    """
    covered_ids: ログから集計した「攻撃が届いた」脆弱性 ID の集合。
    観測可能な脆弱性に対する到達カバレッジを算出して返す。
    """
    covered = set(covered_ids)
    rows = []
    n_covered = 0
    for vid in OBSERVABLE_IDS:
        hit = vid in covered
        if hit:
            n_covered += 1
        rows.append({"id": vid, "type": _type_of(vid), "covered": hit})
    total = len(OBSERVABLE_IDS)
    na = [{"id": vid, "type": _type_of(vid), "reason": reason}
          for vid, reason in NOT_OBSERVABLE.items()]
    return {
        "rows": rows,
        "na": na,
        "covered": n_covered,
        "total": total,
        "percent": round(100.0 * n_covered / total, 1) if total else 0.0,
    }

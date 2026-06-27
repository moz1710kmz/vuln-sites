"""
スキャナ結果の採点（被験スキャナのレポート vs 正解 vuln-map）。

評価ハーネスの最後のピース。harness.py が「自分の攻撃がエンドポイントに届いたか
（到達カバレッジ）」を測るのに対し、こちらは **被験スキャナの検出結果を取り込み、
正解データ（vulndata.VULN_MAP）と突き合わせて採点** する。

算出する指標:
- 検出 (TP):  正解の脆弱性のうち、スキャナが当てたもの
- 見逃し (FN): 正解の脆弱性のうち、スキャナが当てられなかったもの
- 誤検知 (FP): スキャナの指摘のうち、どの正解にも対応しないもの
- Precision = TP / (TP + FP) … 指摘の正確さ
- Recall    = TP / (TP + FN) … 取りこぼしの少なさ（＝検出率）
- F1        = 2PR / (P + R)

取り込める形式: OWASP ZAP JSON / 汎用 JSON / CSV（auto 判定）。
Flask へ依存しない（vulndata / harness と同じデータ層）。
"""

import csv
import io
import json
import re
from urllib.parse import urlsplit

from core.vulndata import VULN_MAP, vuln_in_site, vuln_site_label

# ---------------------------------------------------------------------------
# 種別バケット: スキャナの呼称ゆれ（名称/CWE）を正解の type と同じ土俵に正規化する。
# 上から順に評価し、最初に当たったバケットを採用する。
# ---------------------------------------------------------------------------
_BUCKET_RULES = [
    ("jwt",     r"\bjwt\b|json\s*web\s*token|\bjws\b|bearer\s*token|cwe-?(347|1270)\b"),
    # graphql は sqli/csrf/idor/authz より先に評価する（"GraphQL SQL Injection" 等を graphql に寄せる）。
    ("graphql", r"graphql|graphiql|introspection|\bgql\b"),
    # websocket 固有（WS-1 CSWSH / WS-4 送信者なりすまし）。WS-2 は xss、WS-3 は idor に寄せたいので、
    # 「websocket」単独語ではなく CSWSH / なりすまし等の固有表現だけにマッチさせる。
    ("websocket", r"cswsh|cross[\s-]*site\s*websocket|websocket\s*hijack|spoof|送信者\s*なりすまし|origin\s*未検証|cwe-?(1385|290|345)\b"),
    ("massassign", r"mass\s*assign|over.?post|auto.?bind|excessive\s*data\s*expos|broken\s*object\s*property|\bbopla\b|cwe-?915\b"),
    ("enum",    r"user\s*enumerat|account\s*enumerat|username\s*enumerat|cwe-?20[0-4]\b"),
    ("weakpw",  r"weak\s*password|password\s*(policy|complexity|strength|requirement)|cwe-?521\b"),
    ("cookie",  r"cookie|http\s*-?\s*only|\bsamesite\b|cwe-?(1004|614|1275)\b"),
    ("sqli",    r"sql\s*inject|sqli|cwe-?89\b"),
    ("xss",     r"xss|cross[\s-]*site\s*scripting|cwe-?79\b"),
    ("csrf",    r"csrf|cross[\s-]*site\s*request\s*forgery|cwe-?352\b"),
    ("idor",    r"idor|insecure\s*direct\s*object|broken\s*object\s*level|bola|cwe-?639\b"),
    ("path",    r"path\s*traversal|directory\s*traversal|local\s*file\s*(inclusion|read)|\blfi\b|cwe-?22\b"),
    ("cmd",     r"command\s*inject|os\s*command|\brce\b|remote\s*code|cwe-?78\b"),
    ("sessfix", r"session\s*fixation|cwe-?384\b"),
    ("authz",   r"broken\s*access\s*control|access\s*control|forced\s*brows|missing\s*authoriz|privilege|\bbfla\b|broken\s*function\s*level|cwe-?(285|862|863)\b"),
    ("authn",   r"plain\s*text|clear\s*text|cleartext|hard\s*cod|weak\s*(secret|key|credential|password|auth)|auth\w*\s+weak|password\s*storage|secret\s*key|authentication|credential|cwe-?(256|261|287|312|321|522|798)\b"),
    ("bizlogic", r"business\s*logic|logic\s*flaw|price\s*manipulat|parameter\s*tamper|race\s*condition|insufficient\s*workflow"),
]
_BUCKET_RE = [(name, re.compile(pat, re.I)) for name, pat in _BUCKET_RULES]


def bucket_of(text):
    """脆弱性の呼称（名称や CWE 文字列）からバケット名を返す。該当なしは None。"""
    if not text:
        return None
    for name, rx in _BUCKET_RE:
        if rx.search(text):
            return name
    return None


# ---------------------------------------------------------------------------
# 正解データ（VULN_MAP）を照合しやすい形へ前処理する。
# - endpoint が "/" 始まりならパスのマッチに使う（<id> 等は任意セグメントに変換）。
# - パスを持たない実装レベルの脆弱性（平文保存・弱い鍵）は keywords で識別する。
# ---------------------------------------------------------------------------
def _path_regex(endpoint):
    """ '/blog/<id>/comment' -> ^/blog/[^/]+/comment/?$ 。パスでなければ None。"""
    if not endpoint or not endpoint.startswith("/"):
        return None
    pat = re.sub(r"<[^>]+>", "[^/]+", endpoint.rstrip("/"))
    return re.compile("^" + pat + r"/?$")


# 同じバケット内で取り違えないための識別キーワード。
# パスを持たない正解（AUTH-1/2）や、同一エンドポイントに複数ある正解（JWT 群は /api/* に集中）で
# 種別を取り違えないよう、設定があれば照合時にキーワード一致を追加で要求する。
_GT_KEYWORDS = {
    "AUTH-1": re.compile(r"plain\s*text|clear\s*text|cleartext|password\s*storage|cwe-?(256|312)\b", re.I),
    "AUTH-2": re.compile(r"secret\s*key|hard\s*cod|weak\s*(secret|key)|session\s*signing|cwe-?(321|798)\b", re.I),
    "COOKIE-1": re.compile(r"http\s*-?\s*only|cwe-?1004\b", re.I),
    "COOKIE-2": re.compile(r"\bsecure\b|cwe-?614\b", re.I),
    # GraphQL 群は同一エンドポイント(/graphql)・同一バケットに集まるため、識別キーワードで弁別する。
    "GQL-1": re.compile(r"introspection|__schema|スキーマ", re.I),
    "GQL-2": re.compile(r"graphiql|explorer|playground|エクスプローラ|\bide\b", re.I),
    "GQL-3": re.compile(r"\bbola\b|認可|object\s*level|broken\s*object", re.I),
    "GQL-4": re.compile(r"\bbfla\b|function\s*level|権限昇格|mass\s*assign|マスアサイン", re.I),
    "GQL-5": re.compile(r"sql|inject", re.I),
    "GQL-6": re.compile(r"depth|complexity|batch|deep|nest|denial|\bdos\b|深さ|バッチ|複雑", re.I),
    "GQL-7": re.compile(r"csrf|cross[\s-]*site\s*request", re.I),
    "JWT-1": re.compile(r"alg\s*[:=]?\s*none|none\s*algorithm|unsigned|cwe-?347\b", re.I),
    "JWT-2": re.compile(r"signature.{0,20}(not|no|missing|with(out)?).{0,20}verif|unverified|署名未検証|no\s*signature\s*check", re.I),
    "JWT-3": re.compile(r"weak.{0,12}(secret|key|sign|hmac)|brute|crackab|guessab|弱い|cwe-?326\b", re.I),
    "JWT-4": re.compile(r"sensitive|機微|cleartext|plaintext|pii|information\s*(disclosure|leak|exposure)|sensitive\s*data", re.I),
    "JWT-5": re.compile(r"expir|\bno\s*exp\b|missing\s*exp|無期限|lifetime|long.?lived|never\s*expire", re.I),
    "JWT-6": re.compile(r"confus|混同|rs256.{0,6}hs256|key\s*confusion|algorithm\s*confusion", re.I),
}


def _ground_truth(site="all"):
    out = []
    for v in VULN_MAP:
        if not vuln_in_site(v, site):
            continue
        out.append({
            "id": v["id"],
            "type": v["type"],
            "site": vuln_site_label(v),
            "bucket": bucket_of(v["type"]),
            "path_re": _path_regex(v["endpoint"]),
            "endpoint": v["endpoint"],
            "keywords": _GT_KEYWORDS.get(v["id"]),
        })
    return out


# ---------------------------------------------------------------------------
# スキャナ出力の取り込み（→ 正規化 finding のリスト）
# finding = {"category": str, "path": str|None, "param": str, "raw": str}
# ---------------------------------------------------------------------------
def _norm_path(value):
    """URL/パス文字列からパス部分のみを取り出す。空なら None。"""
    if not value:
        return None
    value = str(value).strip()
    if not value:
        return None
    parts = urlsplit(value)
    path = parts.path if (parts.scheme or parts.netloc) else value.split("?")[0]
    path = path.rstrip("/") or "/"
    if not path.startswith("/"):
        path = "/" + path
    return path


def _first(d, keys):
    for k in keys:
        if k in d and d[k] not in (None, ""):
            return d[k]
    # 大文字小文字を無視した再探索
    lower = {str(k).lower(): v for k, v in d.items()}
    for k in keys:
        if k.lower() in lower and lower[k.lower()] not in (None, ""):
            return lower[k.lower()]
    return None


_CAT_KEYS = ["category", "type", "name", "alert", "issue", "title", "plugin",
             "vuln", "vulnerability", "finding", "cwe", "cweid"]
_URL_KEYS = ["url", "uri", "path", "location", "target", "endpoint", "address", "request_url"]
_PARAM_KEYS = ["param", "parameter", "field", "input", "evidence_param"]


def _mk_finding(category, path, param, raw=None):
    category = (str(category).strip() if category is not None else "")
    return {
        "category": category,
        "path": _norm_path(path),
        "param": (str(param).strip() if param else ""),
        "raw": raw if raw is not None else category,
    }


def _from_generic_obj(obj):
    """汎用 JSON オブジェクト1件 -> finding（CWE は名称に連結してバケット判定を助ける）。"""
    cat = _first(obj, _CAT_KEYS) or ""
    cwe = _first(obj, ["cwe", "cweid", "cwe_id"])
    if cwe and str(cwe) not in str(cat):
        cat = ("%s CWE-%s" % (cat, cwe)).strip()
    return _mk_finding(cat, _first(obj, _URL_KEYS), _first(obj, _PARAM_KEYS), raw=str(obj)[:300])


def _parse_zap(data):
    """OWASP ZAP JSON: {site:[{alerts:[{name,cweid,instances:[{uri,param}]}]}]}。"""
    findings = []
    for site in data.get("site", []):
        for alert in site.get("alerts", []):
            name = alert.get("alert") or alert.get("name") or ""
            cwe = alert.get("cweid") or alert.get("cweId")
            cat = ("%s CWE-%s" % (name, cwe)).strip() if cwe else name
            instances = alert.get("instances") or [{}]
            for inst in instances:
                findings.append(_mk_finding(
                    cat, inst.get("uri") or site.get("@name"),
                    inst.get("param"), raw=name))
    return findings


def _iter_generic(data):
    """汎用 JSON: リスト、または {findings|results|...:[...]} を平らにする。"""
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for key in ("findings", "results", "vulnerabilities", "issues", "alerts", "data"):
            if isinstance(data.get(key), list):
                return data[key]
    return []


def _parse_csv(text):
    findings = []
    reader = csv.DictReader(io.StringIO(text))
    for row in reader:
        clean = {(k or "").strip(): (v or "").strip() for k, v in row.items()}
        findings.append(_from_generic_obj(clean))
    return findings


def load_findings(content, fmt="auto"):
    """
    スキャナ出力（文字列）を正規化 finding のリストへ変換する。
    fmt: "auto" | "zap" | "generic" | "csv"。
    解析できない場合は空リストを返す（例外は投げない）。
    """
    if content is None:
        return []
    text = content.decode("utf-8", "replace") if isinstance(content, bytes) else content
    text = text.strip()
    if not text:
        return []

    def _as_json():
        return json.loads(text)

    if fmt == "csv":
        return _parse_csv(text)
    if fmt in ("zap", "generic", "auto"):
        try:
            data = _as_json()
        except (ValueError, json.JSONDecodeError):
            if fmt == "auto":
                return _parse_csv(text)   # JSON でなければ CSV とみなす
            return []
        if fmt == "zap" or (fmt == "auto" and isinstance(data, dict) and "site" in data):
            return _parse_zap(data)
        return [_from_generic_obj(o) for o in _iter_generic(data) if isinstance(o, dict)]
    return []


# ---------------------------------------------------------------------------
# 照合 & 採点
# ---------------------------------------------------------------------------
def _compatible(finding, gt):
    """finding が正解 gt を指しているとみなせるか。"""
    fb = bucket_of(finding["category"])
    if fb is None or fb != gt["bucket"]:
        return False
    # 識別キーワードがあれば、種別の取り違え防止に一致を要求する。
    if gt["keywords"] is not None:
        text = finding["category"] + " " + finding["raw"]
        if not gt["keywords"].search(text):
            return False
    if gt["path_re"] is not None:
        # パスを持つ脆弱性: パス一致を要求（finding にパスが無ければ種別一致のみで許容）
        if finding["path"] is None:
            return True
        return bool(gt["path_re"].match(finding["path"]))
    return True


def evaluate(findings, site="all"):
    """
    findings: load_findings() の出力。
    site: 採点対象サイト（"all"|"bank"|"ec"）。正解の分母を絞る。
    戻り値: 指標 + 正解ごとの検出状況 + 誤検知/重複の内訳。

    照合は貪欲な 1:1 割り当て: 1つの指摘は最大1つの正解しか満たせない。
    これにより同一エンドポイントに複数の脆弱性がある場合（例 /shop/buy の
    価格改ざんとクーポン競合）に、1件の指摘で両方を二重計上することを防ぐ。
    """
    gts = _ground_truth(site)

    consumed = set()                       # 既に正解に割り当てた finding の index
    matched_by_gt = {}                     # gt id -> finding | None
    for gt in gts:
        chosen = None
        for i, f in enumerate(findings):
            if i not in consumed and _compatible(f, gt):
                chosen = i
                consumed.add(i)
                break
        matched_by_gt[gt["id"]] = findings[chosen] if chosen is not None else None

    rows = []
    tp = 0
    for gt in gts:
        m = matched_by_gt[gt["id"]]
        detected = m is not None
        if detected:
            tp += 1
        rows.append({
            "id": gt["id"], "type": gt["type"], "site": gt["site"],
            "endpoint": gt["endpoint"], "detected": detected,
            "evidence": m["category"] if m else "",
        })

    # 割り当てに使われなかった指摘を「誤検知」と「重複/追加指摘」に分ける。
    false_positives, duplicates = [], []
    for i, f in enumerate(findings):
        if i in consumed:
            continue
        if any(_compatible(f, gt) for gt in gts):
            duplicates.append(f)          # 既に検出済みの正解と同種＝重複（減点しない）
        else:
            false_positives.append(f)     # どの正解にも対応しない＝誤検知

    n_gt = len(gts)
    fn = n_gt - tp
    fp = len(false_positives)
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / n_gt if n_gt else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0

    return {
        "site": site,
        "rows": rows,
        "false_positives": [
            {"category": f["category"] or "(種別不明)", "path": f["path"] or "-", "param": f["param"]}
            for f in false_positives
        ],
        "tp": tp, "fn": fn, "fp": fp,
        "duplicates": len(duplicates),
        "total_gt": n_gt,
        "total_findings": len(findings),
        "precision": round(precision * 100, 1),
        "recall": round(recall * 100, 1),
        "f1": round(f1 * 100, 1),
    }


def evaluate_text(content, fmt="auto", site="all"):
    """文字列を取り込んでそのまま採点する便利関数。"""
    findings = load_findings(content, fmt)
    result = evaluate(findings, site)
    result["fmt"] = fmt
    return result

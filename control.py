"""
VulnBank / VulnEC コントロールパネル（評価ハーネスの制御プレーン）。

役割:
- ログイン付きの管理画面（ポート 8080）。
- VulnBank（app.py / ポート 8081）と VulnEC（app.py / ポート 8082）を「子プロセス」として起動・停止・初期化する。
- ハードオプション（WAF / OTP / メール認証）を個別に選択して起動できる。

検証アプリ自体とは別プロセス・別ポートで動かすため、
パネルが落ちても Bank/EC は動き続ける（その逆も同様）。

注意: これは評価用の制御プレーンであり、固定の app.py を限定された env でのみ起動する
（任意コマンド実行はしない）。ログインで保護する。本番公開しないこと。
"""

import os
import signal
import sqlite3
import subprocess
import sys
import time

from flask import (
    Flask, request, session, redirect, url_for, render_template, abort, flash, Response
)

from core import certmaker
from core import security_features
from core import harness
from core import scanner_eval
from core.envfile import load_env_file

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
load_env_file(BASE_DIR)
DB_PATH = os.path.join(BASE_DIR, "vulnbank.db")
SAMPLE_DIR = os.path.join(BASE_DIR, "samples")

# 「スキャナ採点」の動作確認用に同梱した見本レポート（samples/）。
SAMPLES = {
    "generic": {"file": "scanner_report_generic.json", "fmt": "auto", "site": "all",
                "label": "汎用JSON（両サイト）"},
    "zap": {"file": "scanner_report_zap.json", "fmt": "auto", "site": "ec",
            "label": "OWASP ZAP JSON（VulnEC）"},
    "csv": {"file": "scanner_report.csv", "fmt": "auto", "site": "bank",
            "label": "CSV（VulnBank）"},
    "jwt": {"file": "scanner_report_jwt.json", "fmt": "auto", "site": "board",
            "label": "JWT/登録（VulnBoard）"},
    "graphql": {"file": "scanner_report_graphql.json", "fmt": "auto", "site": "graphql",
                "label": "GraphQL（VulnGraph）"},
}

# 検証アプリの待ち受け設定
BANK_APP_PORT = int(os.environ.get("BANK_APP_PORT", os.environ.get("APP_PORT", "8081")))
EC_APP_PORT = int(os.environ.get("EC_APP_PORT", "8082"))
BOARD_APP_PORT = int(os.environ.get("BOARD_APP_PORT", os.environ.get("API_APP_PORT", "8083")))
GRAPHQL_APP_PORT = int(os.environ.get("GRAPHQL_APP_PORT", "8084"))
APP_PORT = BANK_APP_PORT  # 後方互換: 既存の APP_PORT は VulnBank を指す
APP_BIND = os.environ.get("APP_BIND", "0.0.0.0")
SITES = {
    "bank": {"label": "VulnBank", "port": BANK_APP_PORT, "public_port_env": "BANK_APP_PUBLIC_PORT"},
    "ec": {"label": "VulnEC", "port": EC_APP_PORT, "public_port_env": "EC_APP_PUBLIC_PORT"},
    "board": {"label": "VulnBoard", "port": BOARD_APP_PORT, "public_port_env": "BOARD_APP_PUBLIC_PORT"},
    "graphql": {"label": "VulnGraph", "port": GRAPHQL_APP_PORT, "public_port_env": "GRAPHQL_APP_PUBLIC_PORT"},
}

# パネルの認証情報（環境変数で上書き可能）
PANEL_USER = os.environ.get("PANEL_USER", "admin")
PANEL_PASS = os.environ.get("PANEL_PASS", "panel123")

panel = Flask(__name__)
panel.secret_key = os.environ.get("PANEL_SECRET", "panel-control-secret")
# 検証アプリ(app.py)のデフォルト Cookie 名 "session" と衝突しないよう別名にする。
# ブラウザは Cookie をポートで区別しないため、同名だと :8081-8084 側の操作で
# パネルのセッションが上書き・無効化されてしまう。
panel.config["SESSION_COOKIE_NAME"] = "panel_session"

# 直近のスキャナ採点結果（/scanner で取り込み、/scanner/download で再利用）
_last_scan = None

# 起動中の検証アプリ（site -> subprocess.Popen | None）
_procs = {site: None for site in SITES}
_proc_features = set()    # 起動時に有効化したフィーチャー
_proc_nohint = False       # 起動時にヒント非表示(HIDE_VULN_MAP)を有効化したか
_proc_delivery = {
    "mode": "dev_inbox",
    "smtp_host": "",
    "smtp_port": "587",
    "smtp_username": "",
    "smtp_from": "vulnbank@example.test",
    "smtp_tls": True,
    "aws_region": "ap-northeast-1",
    "ses_from": "vulnbank@example.test",
}


# ---------------------------------------------------------------------------
# 検証アプリのプロセス管理
# ---------------------------------------------------------------------------

def app_running(site=None):
    """検証アプリが稼働中なら True。site 未指定ならどれか1つでも稼働中かを見る。"""
    if site:
        proc = _procs.get(site)
        return proc is not None and proc.poll() is None
    return any(proc is not None and proc.poll() is None for proc in _procs.values())


def _normalize_delivery(delivery):
    delivery = delivery or {}
    mode = delivery.get("mode", "dev_inbox")
    if mode not in ("dev_inbox", "smtp", "ses"):
        mode = "dev_inbox"
    return {
        "mode": mode,
        "smtp_host": delivery.get("smtp_host", "").strip(),
        "smtp_port": delivery.get("smtp_port", "587").strip() or "587",
        "smtp_username": delivery.get("smtp_username", "").strip(),
        "smtp_password": delivery.get("smtp_password", ""),
        "smtp_from": delivery.get("smtp_from", "vulnbank@example.test").strip() or "vulnbank@example.test",
        "smtp_tls": bool(delivery.get("smtp_tls", True)),
        "aws_region": delivery.get("aws_region", "ap-northeast-1").strip() or "ap-northeast-1",
        "aws_access_key_id": delivery.get("aws_access_key_id", "").strip(),
        "aws_secret_access_key": delivery.get("aws_secret_access_key", ""),
        "ses_from": delivery.get("ses_from", "vulnbank@example.test").strip() or "vulnbank@example.test",
    }


def _normalize_sites(sites):
    selected = [s for s in (sites or []) if s in SITES]
    return selected or list(SITES.keys())


def _public_port(site):
    meta = SITES[site]
    try:
        return int(os.environ.get(meta["public_port_env"], str(meta["port"])))
    except ValueError:
        return meta["port"]


def start_app(features, delivery=None, sites=None, nohint=False):
    """
    選択したフィーチャーで検証アプリ(app.py)を子プロセスとして起動する。
    すでに起動中なら一度停止してから起動する（＝再起動）。
    nohint=True で HIDE_VULN_MAP=1 を注入し、ヒント・脆弱性マップを隠す。
    """
    global _proc_features, _proc_delivery, _proc_nohint
    if app_running():
        stop_app()

    # 不正なフィーチャー名は無視（許可リストのみ）
    feats = sorted(set(features) & set(security_features.ALL_FEATURES))
    delivery = _normalize_delivery(delivery)
    sites = _normalize_sites(sites)

    for site in sites:
        env = dict(os.environ)
        env["HOST"] = APP_BIND
        env["PORT"] = str(SITES[site]["port"])
        env["VULN_SITE"] = site
        env["VULN_FEATURES"] = ",".join(feats)   # 空文字なら easy（全バリア無効）
        env["VULN_DELIVERY"] = delivery["mode"]
        env["SMTP_HOST"] = delivery["smtp_host"]
        env["SMTP_PORT"] = delivery["smtp_port"]
        env["SMTP_USERNAME"] = delivery["smtp_username"]
        env["SMTP_PASSWORD"] = delivery["smtp_password"]
        env["SMTP_FROM"] = delivery["smtp_from"]
        env["SMTP_TLS"] = "1" if delivery["smtp_tls"] else "0"
        env["AWS_REGION"] = delivery["aws_region"]
        env["AWS_ACCESS_KEY_ID"] = delivery["aws_access_key_id"]
        env["AWS_SECRET_ACCESS_KEY"] = delivery["aws_secret_access_key"]
        env["SES_FROM"] = delivery["ses_from"]
        env["HIDE_VULN_MAP"] = "1" if nohint else "0"   # ヒント非表示
        env["VULN_TLS"] = "1" if certmaker.tls_enabled(os.environ) else "0"  # パネルと同じ HTTP/HTTPS で子を起動
        env["FLASK_RUN_FROM_CLI"] = "false"

        _procs[site] = subprocess.Popen(
            [sys.executable, os.path.join(BASE_DIR, "app.py")],
            cwd=BASE_DIR, env=env,
        )

    _proc_features = set(feats)
    _proc_nohint = bool(nohint)
    time.sleep(1.0)  # 起動待ち（簡易）
    failed = [SITES[site]["label"] for site in sites if not app_running(site)]
    if failed:
        return False, "起動に失敗しました（%s）。ポート競合などを確認してください。" % ", ".join(failed)
    _proc_delivery = dict(delivery)
    _proc_delivery.pop("smtp_password", None)
    _proc_delivery.pop("aws_secret_access_key", None)
    labels = ", ".join(SITES[site]["label"] for site in sites)
    # トーストが折り返さないよう、本文は起動対象サイトのみ。
    # 機能/配送/ヒント非表示はダッシュボードのメトリクス枠で確認できる。
    return True, "起動しました（%s）" % labels


def stop_app(site=None):
    """検証アプリを停止する。site 未指定なら全サイトを停止する。"""
    global _proc_features, _proc_delivery, _proc_nohint
    targets = [site] if site else list(SITES.keys())
    if not any(app_running(s) for s in targets):
        for s in targets:
            _procs[s] = None
        _proc_features = set()
        _proc_delivery = _normalize_delivery({})
        _proc_nohint = False
        return False, "起動していません。"
    for s in targets:
        proc = _procs.get(s)
        if proc is None or proc.poll() is not None:
            _procs[s] = None
            continue
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)
        _procs[s] = None
    if not app_running():
        _proc_features = set()
        _proc_delivery = _normalize_delivery({})
        _proc_nohint = False
    return True, "停止しました。"


def reset_app():
    """検証アプリを停止し、DB を削除して初期状態に戻す（次回起動時に再シード）。"""
    stop_app()
    try:
        if os.path.exists(DB_PATH):
            os.remove(DB_PATH)
        return True, "初期化しました（DB を削除。次回起動時に再生成されます）。"
    except OSError as e:
        return False, "初期化に失敗しました: %s" % e


# ---------------------------------------------------------------------------
# 認証
# ---------------------------------------------------------------------------

def login_required(view):
    @security_features.wraps(view)
    def wrapper(*args, **kwargs):
        if not session.get("panel_auth"):
            return redirect(url_for("panel_login"))
        return view(*args, **kwargs)
    return wrapper


@panel.route("/login", methods=["GET", "POST"])
def panel_login():
    error = None
    if request.method == "POST":
        if (request.form.get("username") == PANEL_USER
                and request.form.get("password") == PANEL_PASS):
            session["panel_auth"] = True
            return redirect(url_for("dashboard"))
        error = "ユーザー名またはパスワードが違います。"
    return render_template("panel/panel_login.html", error=error)


@panel.route("/logout")
def panel_logout():
    session.clear()
    return redirect(url_for("panel_login"))


# ---------------------------------------------------------------------------
# ダッシュボード & 操作
# ---------------------------------------------------------------------------

@panel.route("/")
@login_required
def dashboard():
    app_host = request.host.split(":")[0]
    tls = certmaker.tls_enabled(os.environ)
    return render_template(
        "panel/panel.html",
        running=app_running(),
        site_statuses={
            site: {
                "label": cfg["label"],
                "port": _public_port(site),
                "running": app_running(site),
            }
            for site, cfg in SITES.items()
        },
        features=sorted(_proc_features),
        delivery=_proc_delivery,
        nohint=_proc_nohint,
        all_features=security_features.ALL_FEATURES,
        app_host=app_host,
        tls=tls,
        app_scheme="https" if tls else "http",
    )


@panel.route("/start", methods=["POST"])
@login_required
def start():
    # 選択されたセキュリティ機能で起動（何も選ばなければバリアなし＝素の状態）。
    features = request.form.getlist("features")
    sites = request.form.getlist("sites")
    delivery = {
        "mode": request.form.get("delivery_mode", "dev_inbox"),
        "smtp_host": request.form.get("smtp_host", ""),
        "smtp_port": request.form.get("smtp_port", "587"),
        "smtp_username": request.form.get("smtp_username", ""),
        "smtp_password": request.form.get("smtp_password", ""),
        "smtp_from": request.form.get("smtp_from", ""),
        "smtp_tls": request.form.get("smtp_tls") == "1",
        "aws_region": request.form.get("aws_region", ""),
        "aws_access_key_id": request.form.get("aws_access_key_id", ""),
        "aws_secret_access_key": request.form.get("aws_secret_access_key", ""),
        "ses_from": request.form.get("ses_from", ""),
    }
    nohint = request.form.get("nohint") == "1"
    ok, message = start_app(features, delivery, sites, nohint=nohint)
    flash(message, "ok" if ok else "err")
    return redirect(url_for("dashboard"))


@panel.route("/stop", methods=["POST"])
@login_required
def stop():
    ok, message = stop_app()
    flash(message, "ok" if ok else "err")
    return redirect(url_for("dashboard"))


@panel.route("/reset", methods=["POST"])
@login_required
def reset():
    ok, message = reset_app()
    flash(message, "ok" if ok else "err")
    return redirect(url_for("dashboard"))


# ---------------------------------------------------------------------------
# 評価ハーネス: 攻撃ログ閲覧 & 自動採点（検証アプリの DB を読む）
# ---------------------------------------------------------------------------

def _read_logs(limit=None, attacks_only=False, ascending=False):
    """検証アプリの request_log を読む。DB/テーブルが無ければ空を返す。"""
    if not os.path.exists(DB_PATH):
        return []
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        sql = "SELECT * FROM request_log"
        if attacks_only:
            sql += " WHERE matched != ''"
        sql += " ORDER BY id %s" % ("ASC" if ascending else "DESC")
        if limit:
            sql += " LIMIT %d" % int(limit)
        rows = conn.execute(sql).fetchall()
        conn.close()
        return [dict(r) for r in rows]
    except sqlite3.Error:
        return []


def _compute_score():
    """ログから到達カバレッジを算出して (result, total_reqs) を返す。"""
    rows = _read_logs()
    covered = set()
    for r in rows:
        if r.get("matched"):
            covered.update(x for x in r["matched"].split(",") if x)
    return harness.score(covered), len(rows)


def _ts():
    return time.strftime("%Y%m%d_%H%M%S")


@panel.route("/logs")
@login_required
def logs():
    attacks_only = request.args.get("attacks") == "1"
    rows = _read_logs(limit=500, attacks_only=attacks_only)
    return render_template("panel/panel_logs.html", rows=rows, attacks_only=attacks_only,
                           running=app_running())


@panel.route("/logs/download")
@login_required
def logs_download():
    """攻撃ログをテキストのログファイルとしてダウンロードする。"""
    attacks_only = request.args.get("attacks") == "1"
    rows = _read_logs(attacks_only=attacks_only, ascending=True)
    lines = [
        "# VulnBank/VulnEC attack log",
        "# generated: %s" % time.strftime("%Y-%m-%d %H:%M:%S"),
        "# filter: %s" % ("attacks only" if attacks_only else "all requests"),
        "# total: %d" % len(rows),
        "",
    ]
    for r in rows:
        target = r["path"] + (("?" + r["query"]) if r.get("query") else "")
        line = '[%s] site=%s %s "%s %s" %s matched=%s' % (
            r.get("ts", ""), r.get("site") or "-", r.get("remote_addr", "-"), r.get("method", ""),
            target, r.get("status", ""), r.get("matched") or "-",
        )
        if r.get("form"):
            line += " form=%s" % r["form"]
        lines.append(line)
    body = "\n".join(lines) + "\n"
    fname = "vulnbank_attacklog_%s.log" % _ts()
    return Response(body, mimetype="text/plain",
                    headers={"Content-Disposition": 'attachment; filename="%s"' % fname})


@panel.route("/score")
@login_required
def score():
    result, total_reqs = _compute_score()
    return render_template("panel/panel_score.html", result=result,
                           total_reqs=total_reqs, running=app_running())


@panel.route("/smoke", methods=["GET", "POST"])
@login_required
def smoke_page():
    """稼働中の各サイトを HTTP で叩くライブ・スモークテスト（システムテスト）。

    GET は説明と「実行」ボタンだけを表示し、攻撃は一切送らない（ナビ遷移で実攻撃が
    走って固まらないようにする）。POST（実行ボタン押下）で初めて稼働中サイトを攻撃する。
    """
    reports = []
    ran = request.method == "POST"
    if ran:
        import smoke
        scheme = "https" if certmaker.tls_enabled(os.environ) else "http"
        for site, meta in SITES.items():
            if not app_running(site):
                continue
            base = "%s://127.0.0.1:%d" % (scheme, meta["port"])
            rep = smoke.run_smoke(base, site=site, features=_proc_features,
                                  delivery_mode=_proc_delivery.get("mode", "dev_inbox"))
            rep["label"] = meta["label"]
            reports.append(rep)
    return render_template("panel/panel_smoke.html", reports=reports, ran=ran,
                           any_running=app_running(), features=sorted(_proc_features),
                           delivery=_proc_delivery.get("mode", "dev_inbox"))


# ---------------------------------------------------------------------------
# スキャナ結果の採点（被験スキャナのレポート vs 正解 vuln-map）
# ---------------------------------------------------------------------------

@panel.route("/scanner", methods=["GET", "POST"])
@login_required
def scanner():
    """被験スキャナの検出結果を取り込み、正解と突き合わせて採点する。"""
    global _last_scan
    if request.method == "POST":
        fmt = request.form.get("fmt", "auto")
        site = request.form.get("site", "all")
        if site not in ("all", "bank", "ec", "board", "graphql"):
            site = "all"
        # アップロードファイルを優先し、無ければ貼り付けテキストを使う
        content = ""
        filename = ""
        up = request.files.get("report")
        if up and up.filename:
            content = up.read().decode("utf-8", "replace")
            filename = up.filename
        if not content.strip():
            content = request.form.get("report_text", "")
            filename = "(貼り付け)"
        if not content.strip():
            flash("スキャナの出力（ファイルまたはテキスト）を指定してください。", "err")
            return redirect(url_for("scanner"))
        result = scanner_eval.evaluate_text(content, fmt=fmt, site=site)
        if result["total_findings"] == 0:
            flash("指摘を1件も読み取れませんでした。形式（auto/zap/generic/csv）を確認してください。", "err")
        else:
            flash("採点しました（指摘 %d 件を取り込み）。" % result["total_findings"], "ok")
        _last_scan = {
            "result": result,
            "fmt": fmt, "site": site, "filename": filename,
            "ts": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        return redirect(url_for("scanner"))

    return render_template("panel/panel_scanner.html", scan=_last_scan,
                           samples=SAMPLES, running=app_running())


@panel.route("/scanner/sample/<key>")
@login_required
def scanner_sample(key):
    """同梱の見本レポートを取り込んで採点する（ワンクリックお試し）。"""
    global _last_scan
    meta = SAMPLES.get(key)
    if not meta:
        abort(404)
    try:
        with open(os.path.join(SAMPLE_DIR, meta["file"]), encoding="utf-8") as f:
            content = f.read()
    except OSError:
        flash("サンプルファイルが見つかりません: %s" % meta["file"], "err")
        return redirect(url_for("scanner"))
    result = scanner_eval.evaluate_text(content, fmt=meta["fmt"], site=meta["site"])
    _last_scan = {
        "result": result, "fmt": meta["fmt"], "site": meta["site"],
        "filename": meta["file"], "ts": time.strftime("%Y-%m-%d %H:%M:%S"),
    }
    flash("サンプル「%s」を採点しました（指摘 %d 件）。" % (meta["label"], result["total_findings"]), "ok")
    return redirect(url_for("scanner"))


@panel.route("/scanner/download")
@login_required
def scanner_download():
    """直近のスキャナ採点結果を PDF でダウンロードする。"""
    if not _last_scan:
        flash("先にスキャナ結果を採点してください。", "err")
        return redirect(url_for("scanner"))
    pdf = _build_scanner_pdf(_last_scan)
    fname = "vulnbank_scanner_score_%s.pdf" % _ts()
    return Response(pdf, mimetype="application/pdf",
                    headers={"Content-Disposition": 'attachment; filename="%s"' % fname})


@panel.route("/score/download")
@login_required
def score_download():
    """採点結果を PDF でダウンロードする。"""
    result, total_reqs = _compute_score()
    pdf = _build_score_pdf(result, total_reqs)
    fname = "vulnbank_score_%s.pdf" % _ts()
    return Response(pdf, mimetype="application/pdf",
                    headers={"Content-Disposition": 'attachment; filename="%s"' % fname})


def _build_score_pdf(result, total_reqs):
    """reportlab で採点レポート PDF を生成して bytes を返す（日本語は標準CIDフォント）。"""
    from io import BytesIO
    from reportlab.lib.pagesizes import A4
    from reportlab.lib import colors
    from reportlab.lib.units import mm
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.cidfonts import UnicodeCIDFont

    FONT = "HeiseiKakuGo-W5"
    pdfmetrics.registerFont(UnicodeCIDFont(FONT))

    buf = BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, topMargin=18 * mm, bottomMargin=18 * mm)
    styles = getSampleStyleSheet()
    h1 = ParagraphStyle("h1", parent=styles["Title"], fontName=FONT, fontSize=16)
    body = ParagraphStyle("body", parent=styles["Normal"], fontName=FONT, fontSize=10, leading=15)
    story = []

    story.append(Paragraph("VulnBank 攻撃到達カバレッジ レポート", h1))
    story.append(Spacer(1, 4 * mm))
    story.append(Paragraph("生成日時: %s" % time.strftime("%Y-%m-%d %H:%M:%S"), body))
    story.append(Paragraph("総リクエスト数: %d" % total_reqs, body))
    story.append(Paragraph(
        "到達カバレッジ: <b>%d / %d</b>（%s%%）" % (result["covered"], result["total"], result["percent"]),
        body))
    story.append(Spacer(1, 6 * mm))

    def _table(rows, header_bg):
        t = Table(rows, hAlign="LEFT", colWidths=[28 * mm, 55 * mm, 80 * mm])
        t.setStyle(TableStyle([
            ("FONTNAME", (0, 0), (-1, -1), FONT),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("BACKGROUND", (0, 0), (-1, 0), header_bg),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.Color(0.96, 0.96, 0.96)]),
        ]))
        return t

    story.append(Paragraph("観測可能な脆弱性", body))
    rows = [["ID", "種別", "到達"]]
    for r in result["rows"]:
        rows.append([r["id"], r["type"], "✓ 到達" if r["covered"] else "✗ 未到達"])
    story.append(_table(rows, colors.HexColor("#1565c0")))
    story.append(Spacer(1, 6 * mm))

    story.append(Paragraph("計測対象外（サーバ側で観測不可・N/A）", body))
    na = [["ID", "種別", "理由"]]
    for r in result["na"]:
        na.append([r["id"], r["type"], r["reason"]])
    story.append(_table(na, colors.HexColor("#6a1b9a")))
    story.append(Spacer(1, 6 * mm))
    story.append(Paragraph(
        "※「到達」は攻撃ペイロードがそのエンドポイントに送られたことを意味し、検出可否そのものとは別です。",
        body))

    doc.build(story)
    return buf.getvalue()


def _build_scanner_pdf(scan):
    """reportlab でスキャナ採点レポート PDF を生成して bytes を返す。"""
    from io import BytesIO
    from reportlab.lib.pagesizes import A4
    from reportlab.lib import colors
    from reportlab.lib.units import mm
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.cidfonts import UnicodeCIDFont

    FONT = "HeiseiKakuGo-W5"
    pdfmetrics.registerFont(UnicodeCIDFont(FONT))
    r = scan["result"]
    site_label = {"all": "VulnBank + VulnEC + VulnBoard + VulnGraph", "bank": "VulnBank",
                  "ec": "VulnEC", "board": "VulnBoard", "graphql": "VulnGraph"}.get(r["site"], r["site"])

    buf = BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, topMargin=18 * mm, bottomMargin=18 * mm)
    styles = getSampleStyleSheet()
    h1 = ParagraphStyle("h1", parent=styles["Title"], fontName=FONT, fontSize=16)
    body = ParagraphStyle("body", parent=styles["Normal"], fontName=FONT, fontSize=10, leading=15)
    story = []

    story.append(Paragraph("スキャナ検出精度レポート", h1))
    story.append(Spacer(1, 4 * mm))
    story.append(Paragraph("生成日時: %s" % time.strftime("%Y-%m-%d %H:%M:%S"), body))
    story.append(Paragraph("対象サイト: %s ／ 取り込み形式: %s ／ 入力: %s"
                           % (site_label, scan["fmt"], scan["filename"]), body))
    story.append(Paragraph("取り込んだ指摘数: %d 件" % r["total_findings"], body))
    story.append(Spacer(1, 4 * mm))
    story.append(Paragraph(
        "Precision <b>%s%%</b>　Recall（検出率） <b>%s%%</b>　F1 <b>%s%%</b>"
        % (r["precision"], r["recall"], r["f1"]), body))
    story.append(Paragraph(
        "検出 %d ／ 見逃し %d ／ 誤検知 %d ／ 重複 %d （正解 %d 件中）"
        % (r["tp"], r["fn"], r["fp"], r["duplicates"], r["total_gt"]), body))
    story.append(Spacer(1, 6 * mm))

    def _table(rows, header_bg, widths):
        t = Table(rows, hAlign="LEFT", colWidths=widths)
        t.setStyle(TableStyle([
            ("FONTNAME", (0, 0), (-1, -1), FONT),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("BACKGROUND", (0, 0), (-1, 0), header_bg),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.Color(0.96, 0.96, 0.96)]),
        ]))
        return t

    story.append(Paragraph("正解ごとの検出状況", body))
    rows = [["ID", "種別", "エンドポイント", "結果"]]
    for row in r["rows"]:
        rows.append([row["id"], row["type"], row["endpoint"],
                     "✓ 検出" if row["detected"] else "✗ 見逃し"])
    story.append(_table(rows, colors.HexColor("#1565c0"), [24 * mm, 38 * mm, 52 * mm, 24 * mm]))
    story.append(Spacer(1, 6 * mm))

    story.append(Paragraph("誤検知（どの正解にも対応しない指摘）", body))
    if r["false_positives"]:
        fp = [["種別", "パス", "パラメータ"]]
        for f in r["false_positives"]:
            fp.append([f["category"], f["path"], f["param"]])
        story.append(_table(fp, colors.HexColor("#b91c1c"), [60 * mm, 50 * mm, 28 * mm]))
    else:
        story.append(Paragraph("なし", body))

    doc.build(story)
    return buf.getvalue()


if __name__ == "__main__":
    host = os.environ.get("PANEL_HOST", "127.0.0.1")
    port = int(os.environ.get("PANEL_PORT", "8080"))
    # 既定 HTTP。VULN_TLS=1 で HTTPS（自己署名・全アプリ共有の1枚）に切り替えられる。
    # ここで生成しておけば、以降に起動する子（Bank/EC/Board）は同じ証明書を共有する。
    ssl_context = certmaker.ssl_context_from_env(os.environ)
    scheme = "https" if ssl_context else "http"
    print("control panel listening on %s://%s:%d" % (scheme, host, port))
    panel.run(debug=False, host=host, port=port, ssl_context=ssl_context)

"""
core: 検証アプリ群が共有する Flask 非依存のロジック層。

エントリポイント（app.py / control.py）と CLI（smoke.py）はリポジトリ直下に置き、
データ・正解・採点・バリア・JWT・証明書などの共通モジュールをこのパッケージに集約する。

- database          … SQLite 初期化・接続
- vulndata          … 脆弱性の正解データ（VULN_MAP / WAF_BYPASS）
- harness           … 攻撃シグネチャ・到達カバレッジ採点
- scanner_eval      … スキャナ結果採点（Precision/Recall/F1）
- jwtutil           … VulnBoard 用の自前 JWT（意図的に壊れた verify）
- certmaker         … 自己署名証明書の生成（HTTPS 化）
- security_features … バリア群（WAF/OTP/メール認証/CSRF/レート制限/2FA/honeypot）。旧 hardmode
"""

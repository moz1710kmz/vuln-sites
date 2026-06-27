# サンプルスキャナレポート

「スキャナ採点」（コントロールパネル `/scanner`）の動作確認用の見本レポートです。
被験スキャナを用意しなくても、これらを取り込めば Precision / Recall / F1 の算出を試せます。

パネルの **「サンプルで試す」ボタン**からワンクリックで採点できます。
ファイルを直接アップロード／貼り付けても同じ結果になります。

| ファイル | 形式 | 採点対象サイト | 想定スコア（目安） |
|---|---|---|---|
| `scanner_report_generic.json` | 汎用 JSON | 全サイト（41件） | 検出 14 / 見逃し 27 / 誤検知 3 ・ P82.4% R34.1% F1 48.3% |
| `scanner_report_zap.json` | OWASP ZAP JSON | VulnEC（16件） | 検出 5 / 見逃し 11 / 誤検知 3 ・ P62.5% R31.2% F1 41.7% |
| `scanner_report.csv` | CSV | VulnBank（9件） | 検出 5 / 見逃し 4 / 誤検知 0 ・ P100.0% R55.6% F1 71.4% |
| `scanner_report_jwt.json` | 汎用 JSON | VulnBoard（10件） | 検出 8 / 見逃し 2 / 誤検知 1 ・ P88.9% R80.0% F1 84.2% |
| `scanner_report_graphql.json` | 汎用 JSON | VulnGraph（7件） | 検出 5 / 見逃し 2 / 誤検知 1 ・ P83.3% R71.4% F1 76.9% |

## それぞれの中身

いずれも「典型的な DAST スキャナの出力」を模しています。
SQLi / XSS / パストラバーサル / コマンドインジェクション / アクセス制御不備などは
当てやすく、**DOM XSS・IDOR・ビジネスロジック・平文保存などは見逃しやすい**という
現実の傾向を反映しています。各レポートには、どの正解にも対応しない
情報系アラート（X-Frame-Options 欠如・バージョン漏えい・CSP 未設定など）を
**誤検知（FP）** として数件混ぜてあります。

## 対応する入力形式

- **汎用 JSON**: `[{ "type"/"category"/"name", "url"/"path", "param", "cwe" }, ...]` の配列。
  `{"findings": [...]}` のようにキーで包まれていても可。
- **OWASP ZAP JSON**: ZAP のレポート出力（`site[].alerts[].instances[]`）。
- **CSV**: `type,url,param,cwe` 等の列を持つヘッダ付き CSV。

種別は名称（"SQL Injection" / "Reflected XSS" 等）または CWE 番号から自動判定します。

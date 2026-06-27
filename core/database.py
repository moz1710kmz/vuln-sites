import sqlite3
import os

from flask import g, has_request_context

# このモジュールは core/ 配下にあるが、DB はリポジトリ直下（core の親）に置く。
# control.py の DB_PATH（ルート基準）と一致させるため、親ディレクトリを基準にする。
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(_ROOT, "vulnbank.db")


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    # リクエスト処理中に開いた接続は g に登録し、teardown_request で確実に閉じる
    # （例外で db.close() に到達せずリークするのを防ぐ）。リクエスト外（control.py /
    # scanner_eval / 起動時 init_db など）では従来どおり呼び出し側が閉じる。
    if has_request_context():
        g.setdefault("_open_dbs", []).append(conn)
    return conn


def init_db():
    conn = get_db()
    c = conn.cursor()

    c.executescript("""
        -- VulnBank 専用ユーザー。残高・メール認証・OTP はここに集約。
        CREATE TABLE IF NOT EXISTS bank_users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            email TEXT,
            role TEXT DEFAULT 'user',
            balance REAL DEFAULT 10000.0,
            secret_note TEXT,
            -- ハードモード用: メール認証状態と認証トークン。
            -- 既定 1（認証済み）にして、easy のシードユーザー/既存挙動に影響を与えない。
            email_verified INTEGER DEFAULT 1,
            verify_token TEXT
        );

        -- VulnEC 専用ユーザー。role（user/staff/admin）とポイント残高を持つ。
        CREATE TABLE IF NOT EXISTS ec_users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            email TEXT,
            role TEXT DEFAULT 'user',
            balance REAL DEFAULT 0.0,
            secret_note TEXT,
            email_verified INTEGER DEFAULT 1,
            verify_token TEXT
        );

        -- VulnBoard 専用ユーザー。JWT 認証で使う。role は board 内の権限。
        CREATE TABLE IF NOT EXISTS board_users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            email TEXT,
            role TEXT DEFAULT 'user',
            secret_note TEXT
        );

        CREATE TABLE IF NOT EXISTS posts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            author_id INTEGER,
            title TEXT,
            body TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            post_id INTEGER,
            author TEXT,
            body TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            product_id INTEGER,
            item TEXT,
            quantity INTEGER,
            price REAL,
            total REAL,
            coupon_used TEXT,
            payment_method TEXT DEFAULT 'points',
            points_used REAL DEFAULT 0,
            ship_name TEXT,
            ship_postal TEXT,
            ship_address TEXT,
            ship_phone TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );

        -- VulnEC の商品レビュー。購入履歴（orders）から投稿する。
        -- 1 注文につき 1 レビュー（order_id にひも付く）。
        CREATE TABLE IF NOT EXISTS reviews (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            product_id INTEGER,
            order_id INTEGER,
            user_id INTEGER,
            author TEXT,
            rating INTEGER,
            body TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS coupons (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            code TEXT UNIQUE,
            discount REAL,
            max_uses INTEGER DEFAULT 1,
            used_count INTEGER DEFAULT 0
        );

        -- VulnEC のカタログ。店舗担当者(staff)/管理者(admin)が編集できる前提。
        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            price REAL,
            description TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );

        -- VulnBoard（タスク管理 SPA）用: ユーザーごとのタスクカード。
        CREATE TABLE IF NOT EXISTS tasks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            title TEXT,
            status TEXT DEFAULT 'todo',
            position INTEGER DEFAULT 0,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );

        -- ハードモード用: 重要操作の OTP（ワンタイムコード）。
        -- bank_users.id を参照。コードは /dev/inbox（擬似SMS/メール）から取得できる。
        CREATE TABLE IF NOT EXISTS otps (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            code TEXT,
            purpose TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );

        -- 評価ハーネス用: 全リクエストのアクセスログ。
        -- matched は harness.classify() が付けた「狙われた脆弱性ID」(カンマ区切り)。
        CREATE TABLE IF NOT EXISTS request_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts DATETIME DEFAULT CURRENT_TIMESTAMP,
            site TEXT,
            method TEXT,
            path TEXT,
            query TEXT,
            form TEXT,
            status INTEGER,
            remote_addr TEXT,
            matched TEXT
        );

        -- VulnBank 振込履歴。出金(out)/入金(in) を 1 送金あたり 2 行記録する。
        -- [NOTE] バリデーションなし: 負の amount もそのまま記録される（BIZ-1 保持）。
        CREATE TABLE IF NOT EXISTS transfer_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            counterparty TEXT,
            direction TEXT,
            amount REAL,
            balance_after REAL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );

        -- VulnBank サポートチャット。顧客(user) と サポート担当(support/admin) の会話を
        -- ルーム単位で保持する。ルーム ID は "R-<1000+顧客user_id>"（顧客 1 名 = 1 ルーム）。
        -- WS-2(格納XSS) のため body は無加工で保存し、配信時も無加工で送る。
        -- WS-3(Room IDOR) の成功判定用に、一部ルームへ一意カナリアをシードする。
        CREATE TABLE IF NOT EXISTS chat_messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            room_id TEXT NOT NULL,
            sender_id INTEGER,
            sender_name TEXT,
            body TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );

        -- VulnBank トップの「お知らせ」。staff/admin が更新できる運用情報。
        -- 利用者向けの掲示なので role=user には読み取り専用、staff/admin が編集する。
        CREATE TABLE IF NOT EXISTS bank_announcements (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            body TEXT,
            published_at DATE,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );
    """)

    cols = {row[1] for row in c.execute("PRAGMA table_info(request_log)").fetchall()}
    if "site" not in cols:
        c.execute("ALTER TABLE request_log ADD COLUMN site TEXT")

    # 既存 DB 向けマイグレーション: ec_users に email_verified / verify_token を追加。
    ec_cols = {row[1] for row in c.execute("PRAGMA table_info(ec_users)").fetchall()}
    if "email_verified" not in ec_cols:
        c.execute("ALTER TABLE ec_users ADD COLUMN email_verified INTEGER DEFAULT 1")
    if "verify_token" not in ec_cols:
        c.execute("ALTER TABLE ec_users ADD COLUMN verify_token TEXT")

    # 既存 DB 向けマイグレーション: orders にレビュー紐付け用の product_id、
    # 支払い方法（ポイント/代引き/併用）・利用ポイント、配送先（お届け先）を追加。
    ocols = {row[1] for row in c.execute("PRAGMA table_info(orders)").fetchall()}
    order_migrations = [
        ("product_id", "INTEGER"),
        ("payment_method", "TEXT DEFAULT 'points'"),
        ("points_used", "REAL DEFAULT 0"),
        ("ship_name", "TEXT"),
        ("ship_postal", "TEXT"),
        ("ship_address", "TEXT"),
        ("ship_phone", "TEXT"),
    ]
    for col, ddl in order_migrations:
        if col not in ocols:
            c.execute(f"ALTER TABLE orders ADD COLUMN {col} {ddl}")

    # Seed bank_users (passwords stored in plaintext — intentional vulnerability)
    # balance はバンク残高。role は VulnBank の 3 階層: user(利用者) / staff(サポート担当) / admin(管理者)。
    #   - user    : 送金できる。ユーザー管理・サポート管理は不可。
    #   - staff   : サポート管理(/support/admin)のみ。送金・ユーザー管理は不可（残高を持たない）。
    #   - admin   : ユーザー管理・サポート管理ができる。送金はしない（残高は監査用に保持）。
    # ※ 既存 ID 順（admin=1, staff=2, alice=3, bob=4, charlie=5, testuser=6）を維持。
    seed_bank_users = [
        ("admin",      "admin123",    "admin@vulnbank.local",   "admin",   50000.0, "Master recovery code: RBK-9C21-4E08-7F3A"),
        ("staff",   "staff123",  "support@vulnbank.local", "staff",     0.0, "サポートデスク担当（送金・ユーザー管理権限なし）"),
        ("alice",      "password123", "alice@example.com",      "user",    10000.0, "My cat's name is Fluffy"),
        ("bob",        "qwerty",      "bob@example.com",        "user",     5000.0, "Remember to call mom"),
        ("charlie",    "charlie2024", "charlie@example.com",    "user",     1500.0, "Server room key: B-104"),
        ("testuser",   "test",        "test@example.com",       "user",      100.0, "Nothing special here"),
    ]
    for u in seed_bank_users:
        c.execute(
            "INSERT OR IGNORE INTO bank_users (username, password, email, role, balance, secret_note) VALUES (?,?,?,?,?,?)",
            u,
        )

    # Seed ec_users (passwords stored in plaintext — intentional vulnerability)
    # role は VulnEC の 3 階層: user(利用者) / staff(店舗担当者) / admin(管理者)。
    # balance はポイント。※ 既存 ID 順（admin=1, staff=2, alice=3, bob=4, charlie=5, testuser=6）を維持。
    seed_ec_users = [
        ("admin",      "admin123",    "admin@vulnec.local",    "admin",     0.0, "Master recovery code: RBK-9C21-4E08-7F3A"),
        ("staff", "staff123",     "shop@vulnec.local",     "staff",     0.0, "店舗バックオフィス担当"),
        ("alice",      "password123", "alice@example.com",     "user",  10000.0, "My cat's name is Fluffy"),
        ("bob",        "qwerty",      "bob@example.com",       "user",   5000.0, "Remember to call mom"),
        ("charlie",    "charlie2024", "charlie@example.com",   "user",   1500.0, "Server room key: B-104"),
        ("testuser",   "test",        "test@example.com",      "user",    100.0, "Nothing special here"),
    ]
    for u in seed_ec_users:
        c.execute(
            "INSERT OR IGNORE INTO ec_users (username, password, email, role, balance, secret_note) VALUES (?,?,?,?,?,?)",
            u,
        )

    # Seed board_users (passwords stored in plaintext — intentional vulnerability)
    # role は board 内権限。admin(1) のタスクには機微情報を含め JWT-2 の影響を示す。
    seed_board_users = [
        ("admin",   "admin123",    "admin@vulnboard.local", "admin", "Master recovery code: RBK-9C21-4E08-7F3A"),
        ("alice",   "password123", "alice@example.com",     "user",  "My cat's name is Fluffy"),
        ("bob",     "qwerty",      "bob@example.com",       "user",  "Remember to call mom"),
        ("charlie", "charlie2024", "charlie@example.com",   "user",  "Server room key: B-104"),
    ]
    for u in seed_board_users:
        c.execute(
            "INSERT OR IGNORE INTO board_users (username, password, email, role, secret_note) VALUES (?,?,?,?,?)",
            u,
        )

    # Seed blog posts (日本語)
    # posts には UNIQUE 制約がないため、起動毎の重複挿入を防ぐべく空のときだけ投入する
    # author_id は ec_users.id を参照（ブログは EC サイトの機能）
    seed_posts = [
        (1, "VulnEC へようこそ！", "オンラインショップをリニューアルオープンしました。会員登録でポイントが貯まり、限定セールやクーポンもご利用いただけます。お得な特典をそろえてお待ちしております。"),
        (2, "オンラインで安全に過ごすために", "パスワードは決して他人と共有しないでください。強力なパスワードを使い、二段階認証を有効にしましょう。"),
        (1, "システムメンテナンスのお知らせ", "土曜日の午前2時〜午前4時（JST）にメンテナンスを実施します。ご不便をおかけします。"),
    ]
    if c.execute("SELECT COUNT(*) FROM posts").fetchone()[0] == 0:
        for p in seed_posts:
            c.execute(
                "INSERT INTO posts (author_id, title, body) VALUES (?,?,?)",
                p,
            )

    # Seed coupons
    c.execute("INSERT OR IGNORE INTO coupons (code, discount, max_uses) VALUES ('SAVE10', 0.10, 100)")
    c.execute("INSERT OR IGNORE INTO coupons (code, discount, max_uses) VALUES ('VIP50', 0.50, 1)")

    # Seed products（VulnEC カタログ。空のときだけ投入）
    seed_products = [
        ("Basic Account Upgrade", 2000.0,
         "VulnEC をもっと快適に使い始めるためのベーシックアップグレード。\n"
         "ストア内の広告を非表示にし、注文履歴を 24 か月間さかのぼって確認できます。\n"
         "お気に入り登録数の上限もなくなるので、欲しいものをいくらでもストックできます。\n"
         "月に数回お買い物をする方の、最初の一歩にちょうどよい入門プランです。"),
        ("Premium Membership", 5000.0,
         "送料無料・お急ぎ便・限定セールの先行アクセスがセットになった人気 No.1 プラン。\n"
         "全国どこへでも送料無料、対象商品はお急ぎ便が使い放題になります。\n"
         "会員限定セールには一般公開より先にアクセスでき、ポイントも常時 2 倍。\n"
         "月に 2 回以上ご利用される方なら、送料分だけで十分に元が取れます。"),
        ("VIP Gold Card", 10000.0,
         "VulnEC の最上位ステータスをまとめた年間メンバーシップ。\n"
         "専任コンシェルジュがお買い物をサポートし、ポイント還元は最大 10%。\n"
         "話題の新商品は優先購入枠でいち早く手に入り、誕生月には特別クーポンをお届けします。\n"
         "24 時間 365 日の優先サポート付きで、特別な体験をひとまとめにしました。"),
    ]
    if c.execute("SELECT COUNT(*) FROM products").fetchone()[0] == 0:
        for p in seed_products:
            c.execute(
                "INSERT INTO products (name, price, description) VALUES (?,?,?)",
                p,
            )

    # Seed sample reviews（商品レビューのサンプル。空のときだけ投入）
    #   実注文に紐づかないデモ用なので order_id / user_id は NULL。商品詳細ページに
    #   最初から購入者レビューが並ぶ。実データなので、利用者が投稿しても消えない。
    seed_reviews = [
        # product_id, author, rating, body, created_at
        (1, "山田 太郎", 5, "広告が消えるだけでこんなに快適になるとは。入門プランなのに満足度が高いです。", "2026-05-02 10:12:00"),
        (1, "佐藤 美咲", 4, "注文履歴を長く残せるのが地味に便利。最初のアップグレードにちょうどよかったです。", "2026-05-18 21:40:00"),
        (2, "鈴木 健一", 5, "送料無料とお急ぎ便だけで十分に元が取れました。もっと早く入ればよかったです。", "2026-04-27 08:05:00"),
        (2, "高橋 由美", 5, "限定セールの先行アクセスが強力。欲しいものを確実に買えるので重宝しています。", "2026-05-21 19:30:00"),
        (2, "伊藤 大輔", 3, "便利ですが、ポイント2倍以外の特典がもう少しあると嬉しいです。", "2026-06-01 12:00:00"),
        (3, "中村 彩",   5, "専任コンシェルジュの対応がとても丁寧。VIP の名に恥じない内容でした。", "2026-04-10 15:22:00"),
        (3, "小林 誠",   4, "還元率が高く、新商品を優先的に買えるのが魅力。年会費分は十分回収できました。", "2026-05-30 09:48:00"),
    ]
    if c.execute("SELECT COUNT(*) FROM reviews").fetchone()[0] == 0:
        for r in seed_reviews:
            c.execute(
                "INSERT INTO reviews (product_id, order_id, user_id, author, rating, body, created_at)"
                " VALUES (?, NULL, NULL, ?, ?, ?, ?)",
                r,
            )

    # Seed tasks（VulnBoard のタスクボード。user_id ごとに割り当て）
    # admin(1) のタスクには運用上の機微な内容を含め、JWT-2（uid 改ざんで他人の
    # タスクを閲覧）の影響が分かるようにしている。
    seed_tasks = [
        (1, "管理コンソールのアクセスレビュー", "doing"),
        (1, "署名鍵のローテーション（secret123 を廃止）", "todo"),
        (1, "インシデント対応訓練", "done"),
        (2, "ランディングページのデザイン", "todo"),
        (2, "ログイン不具合の修正", "doing"),
        (2, "結合テストを書く", "done"),
        (3, "週次レポートの作成", "todo"),
    ]
    if c.execute("SELECT COUNT(*) FROM tasks").fetchone()[0] == 0:
        for pos, (uid, title, status) in enumerate(seed_tasks):
            c.execute(
                "INSERT INTO tasks (user_id, title, status, position) VALUES (?,?,?,?)",
                (uid, title, status, pos),
            )

    # Seed transfer_logs（VulnBank の振込履歴サンプル。空のときだけ投入）
    # alice(2)→admin(1), bob(3)→alice(2) の 2 件分。
    if c.execute("SELECT COUNT(*) FROM transfer_logs").fetchone()[0] == 0:
        seed_logs = [
            # user_id, counterparty, direction, amount, balance_after, created_at
            (3, "admin",  "out", 1000.0, 9000.0,  "2026-06-01 10:00:00"),
            (1, "alice",  "in",  1000.0, 51000.0, "2026-06-01 10:00:00"),
            (4, "alice",  "out",  500.0, 4500.0,  "2026-06-05 14:30:00"),
            (3, "bob",    "in",   500.0, 9500.0,  "2026-06-05 14:30:00"),
        ]
        for log in seed_logs:
            c.execute(
                "INSERT INTO transfer_logs (user_id, counterparty, direction, amount, balance_after, created_at)"
                " VALUES (?,?,?,?,?,?)",
                log,
            )

    # Seed chat_messages（VulnBank サポートチャット。空のときだけ投入）
    #   ルーム ID は "R-<1000+顧客user_id>"。alice(3)→R-1003, bob(4)→R-1004。
    #   bob のルーム(R-1004)のサポート発言に一意カナリア BKSUP-7F3A-9C21 を埋め、
    #   WS-3（Room IDOR: 他人のルームに接続して履歴を窃取）の成功判定に使う。
    if c.execute("SELECT COUNT(*) FROM chat_messages").fetchone()[0] == 0:
        seed_chats = [
            # room_id, sender_id, sender_name, body, created_at
            ("R-1003", 3,    "alice",  "ポイントの有効期限について教えてください。", "2026-06-10 09:00:00"),
            ("R-1003", 2,    "サポート", "alice さま、ポイントは最終利用日から1年間有効です。", "2026-06-10 09:05:00"),
            ("R-1004", 4,    "bob",    "口座のロックを解除したいです。", "2026-06-12 14:20:00"),
            ("R-1004", 2,    "サポート", "本人確認のためお伝えする臨時認証コードは BKSUP-7F3A-9C21 です。窓口でご提示ください。", "2026-06-12 14:25:00"),
        ]
        for chat in seed_chats:
            c.execute(
                "INSERT INTO chat_messages (room_id, sender_id, sender_name, body, created_at)"
                " VALUES (?,?,?,?,?)",
                chat,
            )

    # Seed bank_announcements（VulnBank トップのお知らせ。空のときだけ投入）
    #   従来テンプレートにハードコードしていた 5 件を DB 化し、staff/admin が更新できるようにする。
    if c.execute("SELECT COUNT(*) FROM bank_announcements").fetchone()[0] == 0:
        seed_announcements = [
            # title, body, published_at
            ("【重要】インターネットバンキングの利用推奨環境の更新について",
             "最新のブラウザ（Chrome/Edge/Firefox 最新版）でのご利用をお願いします。旧バージョンではご利用いただけない場合があります。",
             "2026-06-15"),
            ("振込手数料の改定のお知らせ",
             "2026年7月1日（水）より、他行宛て振込手数料を改定いたします。詳細は料金表ページをご確認ください。",
             "2026-06-10"),
            ("【障害復旧】インターネットバンキング一時停止のご報告",
             "6月1日 02:00～04:30（JST）に発生したサービス停止は復旧いたしました。ご不便をおかけし誠に申し訳ございませんでした。",
             "2026-06-01"),
            ("フィッシング詐欺にご注意ください",
             "VulnBank を装ったフィッシングメールが報告されています。不審なメールのリンクは絶対にクリックしないでください。",
             "2026-05-20"),
            ("オンラインバンキングサービスをリニューアルしました",
             "振込・口座情報確認・ログイン設定変更などのオンラインバンキング機能を利用できます。引き続きよろしくお願いいたします。",
             "2026-05-01"),
        ]
        for a in seed_announcements:
            c.execute(
                "INSERT INTO bank_announcements (title, body, published_at) VALUES (?,?,?)",
                a,
            )

    conn.commit()
    conn.close()

"""
VulnGraph — 意図的に脆弱な GraphQL API（site=graphql）。

方針: プロトコルは本物（ariadne / graphql-core）。イントロスペクション・フィールド
サジェスト・spec 準拠のエラー形式はライブラリがそのまま提供する。**脆弱性は GraphQL を
壊すのではなく、resolver と設定の「欠落」で再現**する（JWT を自前で壊した jwtutil.py とは
逆のアプローチ。GraphQL は本物であるべきで、バグは resolver 側に置く）。

仕込んだ GraphQL 固有の脆弱性:
- GQL-1 イントロスペクション有効（スキーマ全開示）          … app 側で introspection=True のまま
- GQL-2 GraphiQL を本番公開（GET /graphql でエクスプローラ）  … app 側
- GQL-3 BOLA: user(id) が他人の email/secretNote/password を認可なしで返す
- GQL-4 BFLA + マスアサインメント: updateUser(id, role) が誰でも admin 昇格を許す
- GQL-5 引数の SQL インジェクション: posts(search/order) を生 SQL に連結
- GQL-6 クエリ深さ/バッチ制限なし（循環ネスト・バッチで DoS / 総当り）  … app 側
- GQL-7 GET でミューテーション受理（CSRF）                  … app 側

HTTP 層（GET/POST・エクスプローラ・バッチ）は app.py が担当し、ここは schema を提供する。
"""

from ariadne import (
    make_executable_schema, QueryType, MutationType, ObjectType,
)

from core.database import get_db

SDL = """
type Query {
  "全ユーザー（機微フィールドを含む＝過剰なデータ露出）"
  users: [User!]!
  "ID 指定でユーザーを取得（所有者チェックなし＝BOLA）"
  user(id: ID!): User
  "投稿の検索（search/order を生 SQL に連結＝SQLi）"
  posts(search: String, order: String): [Post!]!
  post(id: ID!): Post
}

type Mutation {
  "ログイン（レート制限なし。バッチ/エイリアスで総当り可能）"
  login(username: String!, password: String!): AuthPayload
  "登録（role を素通し＝マスアサインメント）"
  register(username: String!, password: String!, role: String): User
  "ユーザー更新（認可なし＝BFLA。role も渡せる＝権限昇格）"
  updateUser(id: ID!, role: String, email: String): User
}

type User {
  id: ID!
  name: String!
  email: String
  role: String
  "機微フィールド: 本来は本人/管理者しか見えないはずのメモ"
  secretNote: String
  "機微フィールド: 平文パスワード（露出してはならない）"
  password: String
  posts: [Post!]!
}

type Post {
  id: ID!
  title: String
  body: String
  author: User
  comments: [Comment!]!
}

type Comment {
  id: ID!
  body: String
  author: String
}

type AuthPayload {
  token: String
  user: User
}
"""

query = QueryType()
mutation = MutationType()
user_type = ObjectType("User")
post_type = ObjectType("Post")


def _row(r):
    return dict(r) if r is not None else None


def _rows(rs):
    return [dict(r) for r in rs]


# ---------------------------------------------------------------------------
# Query resolvers
# ---------------------------------------------------------------------------
@query.field("users")
def resolve_users(_, info):
    db = get_db()
    rows = db.execute("SELECT * FROM bank_users").fetchall()
    db.close()
    return _rows(rows)


@query.field("user")
def resolve_user(_, info, id):
    # [VULN GQL-3] 所有者/権限チェックなし。任意 id の email/secretNote/password を返す（BOLA）。
    db = get_db()
    row = db.execute("SELECT * FROM bank_users WHERE id = ?", (id,)).fetchone()
    db.close()
    return _row(row)


@query.field("posts")
def resolve_posts(_, info, search=None, order=None):
    # [VULN GQL-5] 引数を生 SQL に連結する（GraphQL 引数経由の SQL インジェクション）。
    sql = "SELECT * FROM posts"
    if search is not None:
        sql += " WHERE title LIKE '%" + search + "%' OR body LIKE '%" + search + "%'"
    if order:
        sql += " ORDER BY " + order
    db = get_db()
    rows = db.execute(sql).fetchall()   # サニタイズ・プレースホルダなし
    db.close()
    return _rows(rows)


@query.field("post")
def resolve_post(_, info, id):
    db = get_db()
    row = db.execute("SELECT * FROM posts WHERE id = ?", (id,)).fetchone()
    db.close()
    return _row(row)


# ---------------------------------------------------------------------------
# Mutation resolvers
# ---------------------------------------------------------------------------
@mutation.field("login")
def resolve_login(_, info, username, password):
    # [VULN GQL-6 関連] レート制限なし。バッチ/エイリアスで総当りできる。
    db = get_db()
    row = db.execute(
        "SELECT * FROM bank_users WHERE username = ? AND password = ?", (username, password)
    ).fetchone()
    db.close()
    if row is None:
        return None
    u = dict(row)
    return {"token": "vg-" + str(u["id"]), "user": u}   # 単純な不透明トークン（本筋ではない）


@mutation.field("register")
def resolve_register(_, info, username, password, role=None):
    db = get_db()
    # [VULN GQL-4 関連] クライアント提供の role を素通し（マスアサインメント）。
    cur = db.execute(
        "INSERT INTO bank_users (username, password, email, role) VALUES (?,?,?,?)",
        (username, password, None, role or "user"),
    )
    db.commit()
    row = db.execute("SELECT * FROM bank_users WHERE id = ?", (cur.lastrowid,)).fetchone()
    db.close()
    return _row(row)


@mutation.field("updateUser")
def resolve_update_user(_, info, id, role=None, email=None):
    # [VULN GQL-4] 認可なしで任意ユーザーを更新できる（BFLA）。role も変更でき権限昇格できる。
    db = get_db()
    if role is not None:
        db.execute("UPDATE bank_users SET role = ? WHERE id = ?", (role, id))
    if email is not None:
        db.execute("UPDATE bank_users SET email = ? WHERE id = ?", (email, id))
    db.commit()
    row = db.execute("SELECT * FROM bank_users WHERE id = ?", (id,)).fetchone()
    db.close()
    return _row(row)


# ---------------------------------------------------------------------------
# Field resolvers（DB の列名 → GraphQL フィールド名のマッピングと関連の解決）
# ---------------------------------------------------------------------------
@user_type.field("name")
def resolve_user_name(obj, info):
    return obj.get("username")


@user_type.field("secretNote")
def resolve_user_secret(obj, info):
    return obj.get("secret_note")     # 機微情報をそのまま返す（BOLA で他人の値も取れる）


@user_type.field("posts")
def resolve_user_posts(obj, info):
    db = get_db()
    rows = db.execute("SELECT * FROM posts WHERE author_id = ?", (obj.get("id"),)).fetchall()
    db.close()
    return _rows(rows)


@post_type.field("author")
def resolve_post_author(obj, info):
    db = get_db()
    row = db.execute("SELECT * FROM ec_users WHERE id = ?", (obj.get("author_id"),)).fetchone()
    db.close()
    return _row(row)


@post_type.field("comments")
def resolve_post_comments(obj, info):
    db = get_db()
    rows = db.execute("SELECT * FROM comments WHERE post_id = ?", (obj.get("id"),)).fetchall()
    db.close()
    return _rows(rows)


schema = make_executable_schema(SDL, query, mutation, user_type, post_type)

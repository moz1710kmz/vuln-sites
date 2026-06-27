FROM python:3.12-slim AS base

# 商品画像のURL取り込み→サムネイル生成（curl で取得し、パイプで ImageMagick convert）に使う。
# このパイプのため shell=True が要り、コマンドインジェクション(CMD-1)のデモになる。
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl imagemagick \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# 8080 = コンパネ / 8081 = VulnBank / 8082 = VulnEC / 8083 = VulnBoard / 8084 = VulnGraph
EXPOSE 8080 8081 8082 8083 8084

# コンテナ外からアクセスするため 0.0.0.0 でリッスン
# 既定 HTTPS（自己署名・起動時に certmaker が certs/ に生成）。HTTP にするなら VULN_TLS=0。
ENV PANEL_HOST=0.0.0.0 \
    PANEL_PORT=8080 \
    APP_BIND=0.0.0.0 \
    BANK_APP_PORT=8081 \
    EC_APP_PORT=8082 \
    BOARD_APP_PORT=8083 \
    GRAPHQL_APP_PORT=8084 \
    VULN_TLS=1

# コントロールパネルを起動（パネルから VulnBank/VulnEC を起動/停止する）
CMD ["python", "control.py"]


# --- テスト実行用ステージ -----------------------------------------------------
# base に dev 依存（pytest）を足しただけのイメージ。テストは Docker 上で完結させる。
#   docker compose run --rm tests                 # 全件（既定 pytest -q）
#   docker compose run --rm tests pytest tests/test_vulns.py -q
# multi-stage の既定ターゲットは「最後のステージ」になるため、アプリ用の vuln-suite
# サービスは compose.yaml で target: base を明示してこの test を掴まないようにする。
FROM base AS test

# requirements-dev.txt は base の `COPY . .` で /app に入っている（-r requirements.txt も解決可）。
RUN pip install --no-cache-dir -r requirements-dev.txt

CMD ["python", "-m", "pytest", "-q"]


# --- e2e（ヘッドレスブラウザ）実行用ステージ --------------------------------
# test に playwright と Chromium（＋OS 依存ライブラリ）をビルド時に焼く。
# slim には Chromium の共有ライブラリが無いため `--with-deps` で apt 導入する。
# これにより 2 回目以降は再ダウンロード不要・冪等に e2e を回せる:
#   docker compose run --rm e2e            # = pytest -m e2e（VulnBoard SPA の実 DOM テスト）
FROM test AS e2e

# requirements-e2e.txt は -r requirements-dev.txt + playwright（dev 依存は test で導入済み）。
RUN pip install --no-cache-dir -r requirements-e2e.txt \
    && playwright install --with-deps chromium

CMD ["python", "-m", "pytest", "-m", "e2e"]

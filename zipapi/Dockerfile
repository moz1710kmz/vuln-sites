# VulnEC の「外部住所検索 API」役の独立コンテナ（依存なし・標準ライブラリのみ）。
FROM python:3.12-slim

WORKDIR /app
COPY build_data.py server.py ./

# ビルド時に日本郵便 KEN_ALL を取得し、郵便番号->住所 の JSON に変換して同梱する。
# 取得失敗時は server.py の内蔵サンプルにフォールバック（ビルドは継続）。
RUN python build_data.py

# 8090 = 外部住所検索 API（ブラウザから直接 fetch される）
EXPOSE 8090

ENV ZIP_API_HOST=0.0.0.0 \
    ZIP_API_PORT=8090

CMD ["python", "server.py"]

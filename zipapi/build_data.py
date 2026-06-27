"""
ビルド時に日本郵便の郵便番号データ（KEN_ALL）を取得し、
郵便番号(7桁) -> [都道府県, 市区町村, 町域] の JSON に変換して同梱する。

標準ライブラリのみ（urllib/zipfile/csv）。Docker ビルド時に一度だけ実行され、
生成物 zipdata.json をイメージに焼き込む。取得失敗時はビルドを止めず、
server.py 側の内蔵サンプルにフォールバックさせる（警告を出して exit 0）。
"""

import csv
import io
import json
import os
import sys
import urllib.request
import zipfile

URL = os.environ.get(
    "KEN_ALL_URL",
    "https://www.post.japanpost.jp/service/search/zipcode/download/kogaki/zip/ken_all.zip",
)
OUT = os.environ.get("ZIP_DATA_OUT", "/app/zipdata.json")


def clean_town(t):
    """町域名を整える（補足括弧や『以下に掲載がない場合』等を除去）。"""
    t = (t or "").strip()
    if t in ("以下に掲載がない場合", ""):
        return ""
    for ch in ("（", "("):
        i = t.find(ch)
        if i != -1:
            t = t[:i]
    if t.endswith("一円"):
        t = t[:-2]
    return t


def main():
    try:
        raw = urllib.request.urlopen(URL, timeout=120).read()
        zf = zipfile.ZipFile(io.BytesIO(raw))
        csv_name = next(n for n in zf.namelist() if n.upper().endswith(".CSV"))
        text = zf.read(csv_name).decode("shift_jis")
    except Exception as e:  # ネットワーク不可など。ビルドは止めずサンプルにフォールバック。
        print("build_data: KEN_ALL の取得に失敗（内蔵サンプルにフォールバック）: %s" % e,
              file=sys.stderr)
        return 0

    data = {}
    for row in csv.reader(io.StringIO(text)):
        if len(row) < 9:
            continue
        code = row[2].strip()
        if len(code) != 7 or not code.isdigit():
            continue
        if code in data:
            continue  # 1 郵便番号につき最初の1件を代表に
        data[code] = [row[6].strip(), row[7].strip(), clean_town(row[8])]

    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, separators=(",", ":"))
    print("build_data: %d 件 -> %s" % (len(data), OUT))
    return 0


if __name__ == "__main__":
    sys.exit(main())

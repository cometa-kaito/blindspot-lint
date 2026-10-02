# PyPI への公開手順

2026-10-02 時点で **PyPI には公開していない**。`pip install blindspot-lint` は使えない。
インストールは `pip install git+https://github.com/cometa-kaito/blindspot-lint` を使う。

配布物そのものは検証済みである。

```
twine check  wheel / sdist ともに PASSED
隔離環境に wheel を入れて blindspot コマンドが動作することを確認
wheel の中身は blindspot.py 1ファイルとメタデータのみ
```

## 方法1: Trusted Publishing（トークン不要・未完了）

`.github/workflows/publish.yml` は用意してある。タグを push すると走る。

```bash
git tag v0.1.0 && git push origin v0.1.0
```

ただし 2026-10-02 に3回試して、いずれも `invalid-publisher` で失敗した。
GitHub が送った値は意図どおりで、環境も存在していた。

```
repository    cometa-kaito/blindspot-lint
workflow_ref  cometa-kaito/blindspot-lint/.github/workflows/publish.yml@refs/tags/v0.1.0
```

つまり **PyPI 側の登録が保存されていないか、どこかが食い違っている**。
https://pypi.org/manage/account/publishing/ で確認する。
プロジェクトが PyPI に存在しないので、**「Add a new pending publisher」の側**に
登録されていなければ一致しない。既存プロジェクト用の欄ではない。

| 欄 | 値 | 間違いやすい点 |
|---|---|---|
| PyPI Project Name | `blindspot-lint` | |
| Owner | `cometa-kaito` | |
| Repository name | `blindspot-lint` | |
| Workflow name | `publish.yml` | パスではなくファイル名のみ。`.github/workflows/` は付けない |
| Environment name | （空欄） | ワークフロー側で environment を使っていないので空欄にする |

`test.pypi.org` と `pypi.org` は別サービスで登録も別である。URL を確認する。

登録を直したあとは、タグを打ち直さずに失敗したジョブだけ再実行できる。

```bash
gh run list --workflow publish.yml --limit 1
gh run rerun <RUN_ID> --failed
```

## 方法2: API トークンで手元から上げる（確実）

```bash
python3 -m venv /tmp/pub && /tmp/pub/bin/pip install -q build twine
/tmp/pub/bin/python -m build
/tmp/pub/bin/twine upload dist/*
```

ユーザー名に `__token__`、パスワードに PyPI で作った API トークンを入れる。
トークンはどこにも書き残さない。

## 公開したあとにやること

- `README.md` の「PyPI にはまだ公開していないので…」の一文を削除する
- `pip install blindspot-lint` を使い方の先頭に戻す

## バージョンについて

`0.1.0` はまだ消費されていない。PyPI は一度使ったバージョン番号を再利用できない
（リリースを削除しても同じ番号では上げ直せない）ので、公開が成功するまでは
`0.1.0` のまま試してよい。

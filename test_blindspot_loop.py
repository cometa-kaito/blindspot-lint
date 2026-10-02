# -*- coding: utf-8 -*-
"""blindspot_loop の自己テスト。ollama は使わない。

    python3 test_blindspot_loop.py

生成だけを差し替えて、ループの打ち切り条件と差し戻しの文面を確かめる。
"""
import shutil, sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import blindspot_loop as L

ng = 0

def check(desc, got, want):
    global ng
    if got != want:
        ng += 1
        print(f"  NG  {desc}\n      期待 {want!r}\n      実際 {got!r}")

def ok(desc, cond):
    global ng
    if not cond:
        ng += 1
        print(f"  NG  {desc}")


# ---------------------------------------------------------------- 取り出し
check("python 付きの柵", L.extract_code("説明\n```python\nx = 1\n```\n"), "x = 1\n")
check("言語なしの柵", L.extract_code("```\nx = 2\n```"), "x = 2\n")
check("py の柵", L.extract_code("```py\nx = 3\n```"), "x = 3\n")
check("柵がない", L.extract_code("コードは書きません"), None)
check("最初の柵を採る", L.extract_code("```python\na = 1\n```\nと\n```python\nb = 2\n```"),
      "a = 1\n")

# ---------------------------------------------------------------- 検査
fs = L.inspect("def f(xs):\n    xs.sort()\n")
check("検査器につながっている", [f["rule"] for f in fs], ["BS001"])
check("構文エラーは黙る", L.inspect("def f(:\n"), [])
check("コードがなければ黙る", L.inspect(None), [])

if shutil.which("ruff"):
    rf = L.ruff_check("def f():\n    return undefined_name\n")
    ok("ruff が未定義名を拾う", any(x["rule"] == "F821" for x in rf))
    check("正しいコードでは黙る", L.ruff_check("x = 1\n"), [])
else:
    print("  -- ruff が無いので ruff の確認は飛ばした")

# ---------------------------------------------------------------- 差し戻しの文面
msg = L.feedback_prompt(
    "もとの指示",
    "def f(xs):\n    xs.sort()\n",
    [{"rule": "BS001", "line": 2, "message": "破壊的に変更しています", "hint": "sorted を使う"}],
    [{"rule": "F821", "line": 9, "message": "Undefined name `deque`"}])
ok("もとの指示を保つ", msg.startswith("もとの指示"))
ok("規則と行を含む", "BS001 2行目: 破壊的に変更しています" in msg)
ok("助言を含む", "→ sorted を使う" in msg)
ok("ruff の指摘も含む", "F821 9行目" in msg)
ok("振る舞いを変えるなと言う", "元の仕様と振る舞いを変えないこと" in msg)
ok("コードを囲って渡す", "```python\ndef f(xs):" in msg)


# ---------------------------------------------------------------- ループ
def fake(responses):
    """生成を差し替える。呼ばれるたび responses を順に返す"""
    seq = iter(responses)
    calls = []

    def gen(model, prompt, on_token=None, temperature=None, seed=None):
        calls.append(prompt)
        return next(seq), "stop"
    return gen, calls

CLEAN = "```python\ndef f(xs):\n    return sorted(xs)\n```"
DIRTY = "```python\ndef f(xs):\n    xs.sort()\n    return xs\n```"

_real_gen, _real_warm = L.generate, L.warmup
L.warmup = lambda m: True
try:
    # 初回で黙れば1回で終わる
    L.generate, calls = fake([CLEAN])
    h = L.run_loop("やりたいこと", "m", use_ruff=False)
    check("黙れば1回で終わる", len(h), 1)
    check("生成は1回だけ", len(calls), 1)
    check("指摘は空", h[0]["findings"], [])

    # 鳴れば差し戻して、直れば2回で終わる
    L.generate, calls = fake([DIRTY, CLEAN])
    h = L.run_loop("やりたいこと", "m", use_ruff=False)
    check("直れば2回で終わる", len(h), 2)
    ok("2回目は差し戻しの文面", "【検査結果】" in calls[1])
    ok("差し戻しに BS001 が入る", "BS001" in calls[1])
    check("最終版は黙っている", h[-1]["findings"], [])

    # 直らなければ上限で止まる
    L.generate, calls = fake([DIRTY, DIRTY, DIRTY])
    h = L.run_loop("やりたいこと", "m", rounds=3, use_ruff=False)
    check("上限で止まる", len(h), 3)
    ok("最後まで指摘が残る", h[-1]["findings"] != [])

    # 上限を超えて生成しない
    L.generate, calls = fake([DIRTY, DIRTY])
    h = L.run_loop("やりたいこと", "m", rounds=2, use_ruff=False)
    check("上限の回数しか生成しない", len(calls), 2)

    # コードブロックが返らなければ即やめる
    L.generate, calls = fake(["コードは書きません"])
    h = L.run_loop("やりたいこと", "m", use_ruff=False)
    check("柵がなければ1回でやめる", len(h), 1)
    check("コードは None", h[0]["code"], None)

    # 出来事の順序
    L.generate, calls = fake([DIRTY, CLEAN])
    seen = []
    L.run_loop("やりたいこと", "m", use_ruff=False,
               on_event=lambda k, p: seen.append(k))
    check("出来事の順序",
          seen,
          ["warmup", "round", "code", "findings", "round", "code", "findings", "done"])
finally:
    L.generate, L.warmup = _real_gen, _real_warm

print(f"\n{'すべて期待どおり' if not ng else f'{ng} 件が期待と違う'}")
sys.exit(1 if ng else 0)

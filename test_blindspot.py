# -*- coding: utf-8 -*-
"""blindspot の自己テスト。README に書いた仕様と実装の一致を確認する。

    python3 test_blindspot.py

各ケースは (説明, コード, 期待される規則の集合) の組。
「鳴ってはいけない」ケースを多めに置いている。実コードで鳴る検査器は使われないため。
"""
import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from blindspot import check_source

CASES = [
 # ---------- BS001 引数の破壊的変更 ----------
 ("引数を sort する", "def f(xs):\n    xs.sort()\n    return xs", {"BS001"}),
 ("引数を reverse する", "def f(xs):\n    xs.reverse()", {"BS001"}),
 ("引数を clear する", "def f(xs):\n    xs.clear()", {"BS001"}),
 ("sorted でコピーを作る", "def f(xs):\n    return sorted(xs)", set()),
 ("コピーしてから sort", "def f(xs):\n    xs = list(xs)\n    xs.sort()\n    return xs", set()),
 ("acc=None の正しい実装", "def f(xs, acc=None):\n    if acc is None:\n        acc = []\n    acc.append(1)\n    return acc", set()),
 ("self の変更は対象外", "class C:\n    def f(self):\n        self.clear()", set()),
 ("append は対象外", "def f(xs):\n    xs.append(1)", set()),

 # ---------- BS002 浮動小数点の等価比較 ----------
 ("計算結果どうしの比較", "def f(rows):\n    t = 0.0\n    for _ in rows:\n        t = t + 0.1\n    return t == len(rows) * 0.1", {"BS002"}),
 ("定数との比較は対象外", "def f(s):\n    return s == 0.0", set()),
 ("isclose は正しい", "import math\ndef f(a, b):\n    return math.isclose(a, b)", set()),

 # ---------- 査読で見つかった見落とし・誤検出（2026-10-02） ----------
 ("ヒント文の例そのもの", "def f():\n    return 0.1 + 0.2 == 0.3", {"BS002"}),
 ("平均とリテラルの比較", "def f(xs):\n    return sum(xs) / len(xs) == 0.3", {"BS002"}),
 ("float で初期化した加算器", "def f(it):\n    t = 0.0\n    for x in it:\n        t += x\n    return t == 100.0", {"BS002"}),
 ("copysign の符号判定は対象外", "import math\ndef f(v):\n    return math.copysign(1.0, v) == 1.0", set()),
 ("Path の / は除算ではない", "from pathlib import Path\ndef f(a, b):\n    return Path(a) / 'x' == Path(b) / 'y'", set()),
 ("タプルの比較は対象外", "def f(x, y, im):\n    return (x, y) != im.size", set()),
 ("BS001 後ろの再代入では逃れられない", "def median(xs):\n    xs.sort()\n    m = xs[len(xs) // 2]\n    xs = None\n    return m", {"BS001"}),
 ("__all__ は蓄積ではない", "__all__ = []\ndef _add(n):\n    __all__.append(n)", set()),
 ("除算を変数に出しても検出する", "def f(scores, target):\n    if not scores:\n        return False\n    average = sum(scores) / len(scores)\n    return average == target", {"BS002"}),
 ("変数を2段経由しても検出する", "def f(xs, t):\n    s = sum(xs) / len(xs)\n    a = s\n    return a == t", {"BS002"}),
 ("float を float で初期化した加算器", "def f(items, m):\n    total = 0.0\n    for c in items:\n        total += c\n    return total != m + 1", {"BS002"}),
 ("float 由来からリストを作るのは対象外", "def f(xs, sel):\n    c = int(len(xs) * sel + .5)\n    new = xs[:c]\n    return len(xs) != len(new)", set()),
 ("float 由来からオブジェクトを作るのは対象外", "def f(a, b, cls):\n    q = a / b\n    o = cls(q)\n    return o == b", set()),
 ("n = len(x) は整数", "def f(x, y):\n    n = len(x)\n    return len(y) != n", set()),
 ("整数の floor 除算は対象外", "def f(a, b, c):\n    q = a // b\n    return q == c", set()),
 ("Decimal での比較は正しい", "from decimal import Decimal\ndef f(xs, t):\n    return Decimal(sum(xs)) / Decimal(len(xs)) == Decimal(t)", set()),
 ("decimal.Decimal の形も対象外", "import decimal\ndef f(a, b):\n    return decimal.Decimal(a) / decimal.Decimal(b) == decimal.Decimal(1)", set()),
 ("Fraction も対象外", "from fractions import Fraction\ndef f(a, b):\n    return Fraction(a) / Fraction(b) == Fraction(1, 2)", set()),

 # ---------- BS003 値の is 比較 ----------
 ("要素アクセスどうしの is", "def f(xs, target):\n    for i in range(len(xs)):\n        if xs[i] is target:\n            return i\n    return -1", {"BS003"}),
 ("リテラルとの is", "def f(x):\n    return x is 256", {"BS003"}),
 ("None との is は正しい", "def f(x):\n    return x is None", set()),
 ("True との is は正しい", "def f(x):\n    return x is not True", set()),
 ("Ellipsis との is は正しい", "def f(x):\n    return x is ...", set()),
 ("型比較は正しい", "def f(b):\n    return type(b) is not bytes", set()),
 ("番兵との is は正しい", "_KEEP = object()\ndef f(name):\n    if name is not _KEEP:\n        return name", set()),
 ("全大文字の番兵も対象外", "SENTINEL = object()\ndef f(x):\n    return x is SENTINEL", set()),
 ("連鎖比較で None", "def f(a, b, c):\n    return a is b is c is None", set()),
 ("連鎖比較＋番兵", "_S = object()\ndef f(value=_S, tb=_S):\n    if value is tb is _S:\n        return None\n    return value", set()),
 ("is と == の併用は定石", "def f(v, value):\n    return v is value or v == value", set()),

 # ---------- BS004 ReDoS ----------
 ("入れ子量化子", 'import re\ndef f(s):\n    return re.match(r"(a+)+$", s)', {"BS004"}),
 ("安全な入れ子は対象外", 'import re\ndef f(s):\n    return re.match(r"(\\w+(\\.\\w+)*)", s)', set()),
 ("ふつうの正規表現", 'import re\ndef f(s):\n    return re.match(r"^[a-z]+\\d*$", s)', set()),

 # ---------- BS005 モジュール変数への蓄積 ----------
 ("無制限に貯める", "CACHE = {}\ndef f(x):\n    CACHE.update(x)", {"BS005"}),
 ("上限を設けている", "CACHE = {}\ndef f(k, v):\n    CACHE[k] = v\n    while len(CACHE) > 100:\n        CACHE.popitem()", set()),
 ("_ 始まりも検出する", "_REG = []\ndef f(x):\n    _REG.append(x)", {"BS005"}),
 ("LLMが実際に書く形", "_recorded_paths = []\ndef record(path):\n    global _recorded_paths\n    _recorded_paths.append(path)\n    return len(_recorded_paths)", {"BS005"}),
 ("_ 始まりでも上限があれば対象外", "_REG = []\ndef f(x):\n    _REG.append(x)\n    while len(_REG) > 100:\n        _REG.pop(0)", set()),
 ("ローカル変数は対象外", "out = []\ndef f(items):\n    out = []\n    for i in items:\n        out.append(i)\n    return out", set()),
 ("初期化関数は対象外", "T = []\ndef reg(x):\n    T.append(x)\nreg(1)", set()),

 # ---------- 変数経由での回避（5規則すべてを固定する） ----------
 # 変数代入1行で検出を逃れられないこと。BS002 以外の4規則が逃れていた。
 ("BS001 別名経由", "def f(xs):\n    ys = xs\n    ys.sort()\n    return ys[0]", {"BS001"}),
 ("BS001 コピーは対象外", "def f(xs):\n    ys = list(xs)\n    ys.sort()\n    return ys[0]", set()),
 ("BS001 再代入されたら対象外", "def f(xs):\n    ys = xs\n    ys = [q for q in ys if q]\n    ys.sort()", set()),
 ("BS004 定数経由", 'import re\nPAT = r"(a+)+$"\ndef f(s):\n    return re.match(PAT, s)', {"BS004"}),
 ("BS004 安全な定数は対象外", 'import re\nPAT = r"^[a-z]+$"\ndef f(s):\n    return re.match(PAT, s)', set()),
 ("BS005 別名経由", "xs = []\ndef f(p):\n    ys = xs\n    ys.append(p)", {"BS005"}),
 ("BS005 コピーは対象外", "xs = []\ndef f(p):\n    ys = list(xs)\n    ys.append(p)", set()),
 ("関数属性に貯める（14bが書く形）", "def record(path):\n    if not hasattr(record, 'paths'):\n        record.paths = []\n    record.paths.append(path)\n    return len(record.paths)", {"BS005"}),
 ("関数属性でも上限があれば対象外", "def record(p):\n    if not hasattr(record, 'xs'):\n        record.xs = []\n    record.xs.append(p)\n    while len(record.xs) > 10:\n        record.xs.pop(0)", set()),
 ("self への append は対象外", "class C:\n    def __init__(self):\n        self.xs = []\n    def add(self, v):\n        self.xs.append(v)", set()),
 ("deque(maxlen) は対象外", "from collections import deque\nxs = deque(maxlen=1000)\ndef f(p):\n    xs.append(p)\n    return len(xs)", set()),

 # ---------- ヒントが勧めた直し方が、実際に指摘を消すか ----------
 # 勧めた直し方で指摘が残ると、モデルが収束せず元のコードに逆戻りする。
 # 実測で BS002 の Decimal にこれが起きたので、全部固定しておく。
 ("辞書の上限処理", "CACHE = {}\ndef f(k, v):\n    CACHE.update({k: v})\n    if len(CACHE) > 1000:\n        CACHE.pop(next(iter(CACHE)))\n    return len(CACHE)", set()),
 ("lru_cache に置き換え", "import functools\n\n@functools.lru_cache(maxsize=1000)\ndef f(k):\n    return k * 2", set()),
 ("集合の上限処理", "SEEN = set()\ndef f(p):\n    SEEN.add(p)\n    if len(SEEN) > 1000:\n        SEEN.pop()\n    return len(SEEN)", set()),
 ("関数属性の辞書の上限処理", "def f(k, v):\n    if not hasattr(f, 'c'):\n        f.c = {}\n    f.c.update({k: v})\n    if len(f.c) > 1000:\n        f.c.pop(next(iter(f.c)))\n    return len(f.c)", set()),
 ("関数属性の deque(maxlen) も対象外", "from collections import deque\ndef f(p):\n    if not hasattr(f, 'xs'):\n        f.xs = deque(maxlen=1000)\n    f.xs.append(p)", set()),
 ("上限なしの deque は検出する", "from collections import deque\nxs = deque()\ndef f(p):\n    xs.append(p)", {"BS005"}),
 ("maxlen=None は上限なし", "from collections import deque\nxs = deque(maxlen=None)\ndef f(p):\n    xs.append(p)", {"BS005"}),
 ("defaultdict も検出する", "from collections import defaultdict\nc = defaultdict(list)\ndef f(k, v):\n    c.update({k: v})", {"BS005"}),
]

def main():
    ng = 0
    for desc, code, expect in CASES:
        got = {f.rule for f in check_source(code)}
        ok = got == expect
        if not ok:
            ng += 1
            print(f"  NG  {desc}")
            print(f"      期待 {sorted(expect) or 'なし'} / 実際 {sorted(got) or 'なし'}")
    total = len(CASES)
    print(f"\n{total - ng}/{total} 通過" + ("" if ng else "  — すべて期待どおり"))
    return 1 if ng else 0

if __name__ == "__main__":
    sys.exit(main())

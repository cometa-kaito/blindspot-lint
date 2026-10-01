# -*- coding: utf-8 -*-
"""blindspot — ローカルLLMの盲点を埋める静的検査器

検出項目は恣意的に選んだものではない。6モデル・30欠陥・900件超の実測により
**ローカルLLMの検出率が低く、かつ ruff / pylint / bandit のいずれも拾わない**
欠陥を特定し、そのうち AST で決定的に検出できるものに限定している。

| 規則 | ローカルLLM検出率 | 既存リンター |
|---|---|---|
| BS001 引数の破壊的変更       | 0%  | 拾わない |
| BS002 浮動小数点の等価比較   | 0%  | 拾わない |
| BS003 リテラルとの is 比較   | 0%  | 拾わない |
| BS004 ReDoS（入れ子の量化子）| 2%  | 拾わない |
| BS005 グローバル可変への蓄積 | 0%  | 拾わない |

依存は標準ライブラリのみ。使い方:  python3 blindspot.py FILE [FILE...]
"""
import ast, re, sys, json

# 引数を破壊的に変更しうるメソッド。
# setdefault は「既定値を入れる」用途で kwargs に対して常用されるため除外した
# （標準ライブラリで多数の偽陽性を出した）。
MUTATING = {"sort", "reverse", "clear"}
# sort / reverse / clear に絞った。append / extend / insert / update / add は
# 「引数に貯める」「引数を更新する」のが仕様である関数で常用され、
# 標準ライブラリで多数の偽陽性を出したため外している。
# sort / reverse / clear は「受け取ったものを並べ替える・消す」という、
# 呼び出し元が想定しない副作用になりやすい操作に限定している。

class Finding:
    def __init__(self, rule, line, col, msg, hint):
        self.rule, self.line, self.col, self.msg, self.hint = rule, line, col, msg, hint
    def as_dict(self):
        return {"rule": self.rule, "line": self.line, "col": self.col,
                "message": self.msg, "hint": self.hint}


# 誤差のない数値型。これらで組んだ式は除算があっても float ではない。
EXACT_NUMERIC = {"Decimal", "Fraction"}


def _is_floaty(node):
    """float リテラルか、float を生みうる演算（除算・float() 呼び出し）を含むか

    Decimal / Fraction で組んだ式は除外する。
    【なぜ ― 2026-10-02 の実測で見つけた自己矛盾】
    BS002 のヒントは「整数や Decimal で扱ってください」と勧めている。
    ところが Decimal(a) / Decimal(b) == Decimal(c) には除算が含まれるため、
    **検査器が自分の勧めた修正を指摘し続けていた。**
    qwen2.5-coder:3b はこれで3往復しても収束せず、
    4件中2件は元のコード（float の ==）に逆戻りした。
    """
    for n in ast.walk(node):
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) \
           and n.func.id in EXACT_NUMERIC:
            return False
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) \
           and n.func.attr in EXACT_NUMERIC:
            return False          # decimal.Decimal(...) の形
    for n in ast.walk(node):
        if isinstance(n, ast.Constant) and isinstance(n.value, float):
            return True
        if isinstance(n, ast.BinOp) and isinstance(n.op, ast.Div):
            return True
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == "float":
            return True
    return False


# 入れ子の量化子。(a+)+ (a*)* (a+)* (a|b)+ などの破滅的バックトラック
# 破滅的バックトラックを起こす形: (X+)+ (X*)* (X+)* など、
# 内側が「可変長にマッチしうる1要素」でかつ外側も量化されているもの。
# (\w+(\.\w+)*) のように内側グループが固定の接頭辞を持つ場合は安全なので除外する。
NESTED_QUANT = re.compile(r"\((?:\[[^\]]*\]|\\?\w)[+*]\)[+*]")


class Checker(ast.NodeVisitor):
    def __init__(self, src):
        self.src = src
        self.findings = []
        self.params = []          # 関数ごとの引数名（スタック）
        self.global_mutables = {} # モジュールレベルの可変オブジェクト名 -> 行
        self.shrinking = set()    # どこかで削除・初期化されている名前
        self.cur_func = None      # いま走査中の関数名
        self.local_names = set()  # いまの関数のローカル変数名（同名のグローバルと区別）
        self._bool_stack = []     # いま走査中の and / or 式
        self.module_called = set()  # モジュール直下で呼ばれている関数名（＝初期化処理）
        self.module_funcs = set()   # モジュール直下で定義された関数名
        self.attr_shrinking = set() # 縮む操作がある "関数名.属性名" 

    # ---------- 収集 ----------
    def collect_module_state(self, tree):
        for n in tree.body:
            if isinstance(n, ast.Assign) and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name):
                v = n.value
                if (isinstance(v, (ast.List, ast.Dict, ast.Set)) or
                        (isinstance(v, ast.Call) and isinstance(v.func, ast.Name)
                         and v.func.id in {"list", "dict", "set"})):
                    self.global_mutables[n.targets[0].id] = n.lineno
        # モジュール直下で呼ばれている関数は初期化処理とみなす
        for n in tree.body:
            expr = n.value if isinstance(n, ast.Expr) else None
            if isinstance(expr, ast.Call) and isinstance(expr.func, ast.Name):
                self.module_called.add(expr.func.id)
            if isinstance(n, (ast.For, ast.If, ast.While)):
                for sub in ast.walk(n):
                    if isinstance(sub, ast.Call) and isinstance(sub.func, ast.Name):
                        self.module_called.add(sub.func.id)
        for n in tree.body:
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self.module_funcs.add(n.name)
        for n in ast.walk(tree):
            # 縮む操作があるなら「無制限に蓄積」ではない
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) \
               and n.func.attr in {"clear", "pop", "popitem", "remove", "discard"} \
               and isinstance(n.func.value, ast.Name):
                self.shrinking.add(n.func.value.id)
            # 関数属性に対する縮む操作（record.paths.pop() など）
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) \
               and n.func.attr in {"clear", "pop", "popitem", "remove", "discard"} \
               and isinstance(n.func.value, ast.Attribute) \
               and isinstance(n.func.value.value, ast.Name):
                self.attr_shrinking.add(f"{n.func.value.value.id}.{n.func.value.attr}")
            if isinstance(n, ast.Delete):
                for t in n.targets:
                    base = t.value if isinstance(t, ast.Subscript) else t
                    if isinstance(base, ast.Name):
                        self.shrinking.add(base.id)

    # ---------- 走査 ----------
    def visit_FunctionDef(self, node):
        a = node.args
        names = {p.arg for p in (a.posonlyargs + a.args + a.kwonlyargs)}
        if a.vararg: names.add(a.vararg.arg)
        if a.kwarg: names.add(a.kwarg.arg)
        # 関数内で引数名に別のオブジェクトを再代入している場合、
        # それ以降は呼び出し元のオブジェクトではない。
        #   def f(acc=None):
        #       if acc is None: acc = []      ← 可変デフォルト引数の正しい直し方
        #       acc.append(x)                 ← これは破壊的変更ではない
        # 誤検出するとモデルに不要な修正を促して壊しかねないので、保守的に外す。
        rebound = set()
        for sub in ast.walk(node):
            if isinstance(sub, ast.Assign):
                for tgt in sub.targets:
                    if isinstance(tgt, ast.Name) and tgt.id in names:
                        rebound.add(tgt.id)
        names -= rebound
        # self / cls は「呼び出し元のオブジェクトを勝手に変える」話とは別。
        # メソッドが自分の状態を変えるのは当然の設計である。
        names -= {"self", "cls"}
        # 関数内で代入される名前はローカル。同名のモジュール変数と混同しない
        prev_local = self.local_names
        self.local_names = {tg.id for sub in ast.walk(node)
                            if isinstance(sub, (ast.Assign, ast.AugAssign, ast.AnnAssign))
                            for tg in (sub.targets if isinstance(sub, ast.Assign) else [sub.target])
                            if isinstance(tg, ast.Name)}
        self.local_names -= {n.id for sub in ast.walk(node) if isinstance(sub, ast.Global)
                             for n in [ast.Name(id=x) for x in sub.names]}
        self.params.append(names)
        prev, self.cur_func = self.cur_func, node.name
        self.generic_visit(node)
        self.cur_func = prev
        self.local_names = prev_local
        self.params.pop()
    visit_AsyncFunctionDef = visit_FunctionDef

    def _cur_params(self):
        return self.params[-1] if self.params else set()

    def visit_Call(self, node):
        f = node.func
        if isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name):
            name, attr = f.value.id, f.attr
            # BS001 引数の破壊的変更
            if attr in MUTATING and name in self._cur_params():
                self.findings.append(Finding(
                    "BS001", node.lineno, node.col_offset,
                    f"引数 `{name}` を `{attr}()` で破壊的に変更しています",
                    f"呼び出し元のオブジェクトが書き換わります。"
                    f"{'sorted(%s) を使う' % name if attr == 'sort' else 'コピーを作る（%s = list(%s)）' % (name, name)}か、"
                    f"変更することを関数名・ドキュメントで明示してください"))
            # BS005 グローバル可変への無制限蓄積
            # モジュール読み込み時に一度だけ構築される表（登録関数など）は対象外。
            # 判定: その関数がモジュール直下で即座に呼ばれていれば初期化とみなす。
            #
            # 【`_` 始まりを除外しない理由 ― 2026-10-01 の実測で方針を変えた】
            # 以前は `_` 始まりの名前を「非公開のレジストリだから意図的」として
            # 除外していた。しかし LLM に「記録を貯める関数」を書かせると
            # **5回中4回が `_recorded_paths = []` と書く**。
            # つまり除外していたのは、この検査器がいちばん見るべき形だった。
            #
            # 除外を外すと標準ライブラリ155ファイルで4件増える
            # （threading._threading_atexits / turtle._CFG / typing._cleanups。
            # いずれも意図的なレジストリ）。
            # 1ファイルあたり 0.052 → 0.077 件。
            # この検査器の用途は LLM の生成コードを見ることなので、
            # 助言4件と引き換えに主要な形を拾うほうを選んだ。
            if attr in {"append", "extend", "update", "add"} \
               and name in self.global_mutables and name not in self.shrinking \
               and name not in self.local_names \
               and self.params and self.cur_func not in self.module_called:
                self.findings.append(Finding(
                    "BS005", node.lineno, node.col_offset,
                    f"モジュール変数 `{name}` に追加し続けており、取り除く処理がありません",
                    f"`{name}` は {self.global_mutables[name]} 行目で定義されています。"
                    "長時間動かすとメモリが増え続けます。上限を設けるか明示的に解放してください"))
        # BS005 の第2の形：関数属性に貯める（record.paths.append(...)）
        #
        # 【なぜ必要か ― 2026-10-02 の実測】
        # 「記録を貯める関数」を5モデルに書かせたら、設計が5通りに分かれた。
        #   1.5b        モジュール変数 recorded_paths = []      ← 従来の BS005 で拾える
        #   14b         関数属性 record.recorded_paths = []     ← これ。拾えていなかった
        #   3b/非特化    クラス self.records                     ← 拾わない（下記）
        #   7b          ファイルに追記                           ← 別の欠陥クラス
        # 無制限の蓄積は5モデル中4モデルに存在したのに、拾えたのは1つだけだった。
        #
        # 関数属性はモジュール変数と同じ寿命（関数は解放されない）なので、
        # 同じ欠陥である。標準ライブラリ155ファイルでの出現は **0件** なので
        # 偽陽性の危険がない。
        #
        # 一方 self.attr.append() は拾わない。標準ライブラリに103件あり、
        # コレクションを持つクラスの普通の書き方である。
        # インスタンスの寿命が蓄積を区切るので、同じ欠陥とは言えない。
        if isinstance(f, ast.Attribute) and f.attr in {"append", "extend", "update", "add"} \
           and isinstance(f.value, ast.Attribute) and isinstance(f.value.value, ast.Name):
            holder, attr = f.value.value.id, f.value.attr
            if holder in self.module_funcs \
               and f"{holder}.{attr}" not in self.attr_shrinking:
                self.findings.append(Finding(
                    "BS005", node.lineno, node.col_offset,
                    f"関数属性 `{holder}.{attr}` に追加し続けており、取り除く処理がありません",
                    f"関数 `{holder}` は解放されないので、`{holder}.{attr}` は"
                    "モジュール変数と同じように増え続けます。"
                    "上限を設けるか明示的に解放してください"))
        # BS004 ReDoS
        if isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name) and f.value.id == "re":
            if node.args and isinstance(node.args[0], ast.Constant) \
               and isinstance(node.args[0].value, str):
                pat = node.args[0].value
                if NESTED_QUANT.search(pat):
                    self.findings.append(Finding(
                        "BS004", node.lineno, node.col_offset,
                        f"正規表現 `{pat}` に入れ子の量化子があります",
                        "特定の入力で照合時間が指数的に増えます（ReDoS）。"
                        "量化子の入れ子をなくすか、入力長に上限を設けてください"))
        self.generic_visit(node)

    def visit_Subscript(self, node):
        self.generic_visit(node)

    def visit_Assign(self, node):
        # 引数への要素代入（xs[i] = ...）は heapq / bisect のように
        # 「引数を変更するのが仕様」の関数で常用されるため対象外とした。
        # メソッド呼び出しによる破壊的変更だけを見る。
        self.generic_visit(node)

    def _paired_with_eq(self, cmp_node):
        """同じ or / and の中で == による比較も行っているか"""
        for parent in self._bool_stack:
            if cmp_node in parent.values:
                for other in parent.values:
                    if other is cmp_node: continue
                    for sub in ast.walk(other):
                        if isinstance(sub, ast.Compare) and any(
                                isinstance(o, (ast.Eq, ast.NotEq)) for o in sub.ops):
                            return True
        return False

    def visit_BoolOp(self, node):
        self._bool_stack.append(node)
        self.generic_visit(node)
        self._bool_stack.pop()

    def visit_Compare(self, node):
        # 連鎖比較 `a is b is None` は最終的に None 判定なので正しい用法。
        # 比較に関わるどこかに None / True / False、あるいは番兵らしい名前が
        # あれば is の誤用ではない（`value is tb is _sentinel` の形）。
        chain = [node.left] + list(node.comparators)
        def _chain_ok(x):
            if isinstance(x, ast.Constant):
                return x.value is None or isinstance(x.value, bool)
            nm = x.id if isinstance(x, ast.Name) else (
                 x.attr if isinstance(x, ast.Attribute) else "")
            return bool(nm) and (nm.startswith("_") or nm.isupper())
        if len(node.ops) > 1 and any(_chain_ok(x) for x in chain):
            self.generic_visit(node); return
        for op, right in zip(node.ops, node.comparators):
            # BS002 浮動小数点の等価比較
            # 0.0 や 1.0 との比較は「ちょうどその値か」を見る正当な用途が多い
            # （copysign(1.0, f) == 1.0 で符号を見る等）。誤差が問題になるのは
            # 計算結果どうしの比較なので、片側が単純な定数なら除外する。
            def is_plain_const(x):
                return isinstance(x, ast.Constant) or (
                    isinstance(x, ast.UnaryOp) and isinstance(x.operand, ast.Constant))
            if isinstance(op, (ast.Eq, ast.NotEq)) \
               and (_is_floaty(node.left) or _is_floaty(right)) \
               and not (is_plain_const(node.left) or is_plain_const(right)):
                self.findings.append(Finding(
                    "BS002", node.lineno, node.col_offset,
                    "浮動小数点の値を == / != で比較しています",
                    "丸め誤差のため一致しないことがあります（0.1 を3回足しても 0.3 になりません）。"
                    "math.isclose() を使うか、整数や Decimal で扱ってください。"
                    "math.isclose を使うなら `import math` を、"
                    "Decimal を使うなら `from decimal import Decimal` を忘れないでください"))
            # BS003 値の比較に is を使っている
            # None / True / False との is は正しい用法なので除外する。
            # それ以外（リテラル・変数同士）は同一性と等価性の混同にあたる。
            # `a is b or a == b` は同一性で高速に判定してから等価性を見る定石。
            # 同じ親 BoolOp の中に == 比較があれば、is の誤用ではない。
            if isinstance(op, (ast.Is, ast.IsNot)) and not self._paired_with_eq(node):
                def is_singleton(x):
                    # None / True / False / Ellipsis との is は正しい用法
                    return isinstance(x, ast.Constant) and (
                        x.value is None or isinstance(x.value, bool)
                        or x.value is Ellipsis)
                def is_typeish(x):
                    # type(a) is B / クラスオブジェクト同士の比較は正しい用法。
                    # 大文字始まりの名前・属性アクセスは型とみなして除外する。
                    if isinstance(x, ast.Call) and isinstance(x.func, ast.Name) \
                       and x.func.id == "type":
                        return True
                    if isinstance(x, ast.Name) and x.id[:1].isupper():
                        return True
                    if isinstance(x, ast.Attribute) and x.attr[:1].isupper():
                        return True
                    return False
                # 変数同士の is は「番兵との比較」「同一性そのものを見たい」という
                # 正しい用法が大半を占める（標準ライブラリで337件中ほぼ全て）。
                # 誤検出を避けるため、**リテラルとの is 比較**に限定する。
                # 番兵オブジェクト（_sentinel / _empty など、モジュール定数や
                # クラス属性）との is は正しい用法。標準ライブラリで337件あり、
                # ほぼ全てがこれだった。
                # 一方 `xs[i] is target` のように **要素アクセスや引数** が
                # 絡む is は、値の比較のつもりで書かれた誤用である。
                def looks_sentinel(x):
                    """番兵オブジェクトらしい名前か（_KEEP, _sentinel, _empty 等）"""
                    nm = x.id if isinstance(x, ast.Name) else (
                         x.attr if isinstance(x, ast.Attribute) else "")
                    return bool(nm) and (nm.startswith("_") or nm.isupper())
                def is_valueish(x):
                    """値（番兵ではなく中身）を指していそうか"""
                    if looks_sentinel(x):
                        return False
                    if isinstance(x, ast.Subscript):      # xs[i]
                        return True
                    if isinstance(x, ast.Name) and x.id in self._cur_params():
                        return True                        # 関数引数
                    return False
                lit = next((x for x in (node.left, right)
                            if isinstance(x, ast.Constant)), None)
                valueish = is_valueish(node.left) and is_valueish(right)
                if (lit is not None or valueish) \
                   and not (is_singleton(node.left) or is_singleton(right)
                            or is_typeish(node.left) or is_typeish(right)):
                    self.findings.append(Finding(
                        "BS003", node.lineno, node.col_offset,
                        (f"リテラル `{lit.value!r}` を is で比較しています" if lit is not None
                         else "値どうしを is で比較しています"),
                        "is は同一性（同じオブジェクトか）の比較です。"
                        "小さな整数や短い文字列では処理系のキャッシュで偶然 True になりますが、"
                        "保証されていません。値が等しいかを見たいなら == を使ってください。"
                        "None / True / False との比較だけが is の正しい用法です"))
        self.generic_visit(node)


def check_source(src, filename="<string>"):
    tree = ast.parse(src, filename)
    c = Checker(src)
    c.collect_module_state(tree)
    c.visit(tree)
    return sorted(c.findings, key=lambda f: (f.line, f.rule))


def main(argv):
    as_json = "--json" in argv
    files = [a for a in argv[1:] if not a.startswith("-")]
    if not files:
        print(__doc__); return 2
    total, out = 0, []
    for path in files:
        src = open(path, encoding="utf-8").read()
        try:
            fs = check_source(src, path)
        except SyntaxError as e:
            print(f"{path}: 構文エラー {e}"); continue
        total += len(fs)
        if as_json:
            out += [dict(file=path, **f.as_dict()) for f in fs]
        else:
            for f in fs:
                print(f"{path}:{f.line}:{f.col}: {f.rule} {f.msg}")
                print(f"    → {f.hint}")
    if as_json:
        print(json.dumps(out, ensure_ascii=False, indent=2))
    return 1 if total else 0


def cli():
    """コンソールスクリプトの入口（pyproject.toml の [project.scripts] から呼ばれる）"""
    sys.exit(main(sys.argv))


if __name__ == "__main__":
    cli()

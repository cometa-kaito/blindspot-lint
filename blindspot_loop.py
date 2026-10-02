# -*- coding: utf-8 -*-
"""blindspot-loop — ローカルLLMに書かせ、検査し、直るまで差し戻す

    blindspot-loop                       画面を開く（学生向け）
    blindspot-loop "やりたいことを書く"   そのまま端末で回す

手元の ollama にコードを書かせ、blindspot と ruff にかけ、
**両方が黙るまで**指摘を本人に差し戻す。コードは手元から出ない。

なぜ ruff を併用するのか（既定で有効、--no-ruff で切れる）:
  小さいモデルは指摘どおりに直す過程で `import` を落とすことがある。
  実測では、助言を直しやすい形に変えた途端、最小のモデルが4件中3件で
  実行不能なコードを返した。`ruff check --select F821` を同じループに
  入れると、観測された3件すべてで害が消えた。

なぜ生成トークン数に上限を置くのか:
  ollama の既定は無制限で、特定の（モデル, プロンプト, seed）の組で
  生成が終わらなくなる。退化の中身は問題点を100項目まで番号を振り続ける
  もので、正当な出力ではない。実測では正常な応答の95%が599トークン以内
  に収まったため 1024 で打ち切る。
"""
import argparse, json, pathlib, re, subprocess, sys, time, urllib.error, urllib.request

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from blindspot import check_source

OLLAMA = "http://127.0.0.1:11434"
NUM_PREDICT = 1024
TEMPERATURE = 0.2
RUFF_SELECT = "F821"
MAX_ROUNDS = 3
TIMEOUT = 400


# ---------------------------------------------------------------- ollama

def _req(path, payload=None, timeout=TIMEOUT, stream=False):
    url = OLLAMA + path
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(url, data=data,
                                 headers={"Content-Type": "application/json"})
    r = urllib.request.urlopen(req, timeout=timeout)
    if stream:
        return r
    return json.loads(r.read().decode("utf-8"))


def list_models():
    try:
        return [m["name"] for m in _req("/api/tags", timeout=10)["models"]]
    except Exception:
        return []


def warmup(model):
    """モデルをメモリに載せてから本番の生成を始める

    モデルを切り替えた直後の最初の1件だけが応答しなくなることがある。
    prompt を空にした /api/generate は読み込みだけを行う。失敗しても続ける。
    """
    try:
        _req("/api/generate", {"model": model, "prompt": "", "stream": False},
             timeout=TIMEOUT)
        return True
    except Exception:
        return False


def generate(model, prompt, on_token=None, temperature=TEMPERATURE, seed=None):
    """1回生成する。on_token があれば届いた端から渡す"""
    body = {"model": model, "prompt": prompt, "stream": bool(on_token),
            "options": {"temperature": temperature, "num_predict": NUM_PREDICT}}
    if seed is not None:
        body["options"]["seed"] = seed
    if not on_token:
        r = _req("/api/generate", body)
        return r.get("response", ""), r.get("done_reason", "")
    out, done_reason = [], ""
    resp = _req("/api/generate", body, stream=True)
    for raw in resp:
        if not raw.strip():
            continue
        try:
            chunk = json.loads(raw.decode("utf-8"))
        except Exception:
            continue
        piece = chunk.get("response", "")
        if piece:
            out.append(piece)
            on_token(piece)
        if chunk.get("done"):
            done_reason = chunk.get("done_reason", "")
    return "".join(out), done_reason


# ---------------------------------------------------------------- 検査

def extract_code(text):
    m = re.findall(r"```(?:python|py)?\s*\n(.*?)```", text, re.S)
    return m[0] if m else None


def ruff_check(code):
    """未定義の名前と構文エラーだけを見る。ruff が無ければ黙って諦める"""
    if not code:
        return []
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        p = pathlib.Path(d) / "c.py"
        p.write_text(code, encoding="utf-8")
        try:
            r = subprocess.run(["ruff", "check", "--select", RUFF_SELECT,
                                "--output-format", "json", str(p)],
                               capture_output=True, text=True, timeout=30)
            out = json.loads(r.stdout) if r.stdout.strip() else []
        except Exception:
            return []
    return [{"rule": x.get("code") or "invalid-syntax",
             "line": (x.get("location") or {}).get("row", 0),
             "message": x.get("message", "")} for x in out]


def inspect(code):
    if not code:
        return []
    try:
        return [f.as_dict() for f in check_source(code)]
    except SyntaxError:
        return []


def feedback_prompt(task_prompt, code, findings, ruff_findings=()):
    """差し戻しの文面。実験で用いたものと同一にしてある

    文面は結果を大きく変える。実測では、助言の書き方を変えただけで
    解消率が 22% から 100% に動いた（検出ロジック・モデル・温度・乱数種は
    据え置き、初回の生成物はバイト単位で同一）。ここを安易に書き換えない。
    """
    lines = "\n".join(f"- {f['rule']} {f['line']}行目: {f['message']}\n  → {f['hint']}"
                      for f in findings)
    if ruff_findings:
        rl = "\n".join(f"- {f['rule']} {f['line']}行目: {f['message']}"
                       for f in ruff_findings)
        lines = (lines + "\n" if lines else "") + rl
    return (f"{task_prompt}\n\n"
            f"あなたの回答に対して静的検査を行ったところ、次の指摘がありました。\n\n"
            f"```python\n{code}\n```\n\n"
            f"【検査結果】\n{lines}\n\n"
            f"これらを修正してください。**元の仕様と振る舞いを変えないこと。**\n"
            f"指摘箇所以外は変更しないでください。"
            f"修正後の完全なコードをコードブロックで示してください。")


TASK_WRAPPER = ("{task}\n\n"
                "Python で実装し、完全なコードをコードブロックで示してください。")


# ---------------------------------------------------------------- ループ

def run_loop(task, model, rounds=MAX_ROUNDS, use_ruff=True, on_event=None,
             temperature=TEMPERATURE, seed=None):
    """生成 → 検査 → 差し戻し を、検査器が黙るまで繰り返す

    on_event(kind, payload) に逐次通知する。kind は
    warmup / round / token / code / findings / done のいずれか。
    返り値は各ラウンドの記録のリスト。
    """
    def emit(kind, **payload):
        if on_event:
            on_event(kind, payload)

    emit("warmup", model=model)
    warmup(model)

    prompt = TASK_WRAPPER.format(task=task)
    history = []
    for rd in range(rounds):
        emit("round", round=rd, prompt=prompt)
        t0 = time.time()
        text, done_reason = generate(
            model, prompt,
            on_token=(lambda p: emit("token", round=rd, text=p)) if on_event else None,
            temperature=temperature, seed=seed)
        code = extract_code(text)
        emit("code", round=rd, code=code, raw=text, done_reason=done_reason,
             wall_s=round(time.time() - t0, 1))

        if code is None:
            emit("done", reason="no_code", round=rd, code=None)
            history.append({"round": rd, "code": None, "findings": [], "ruff": []})
            return history

        fs = inspect(code)
        rf = ruff_check(code) if use_ruff else []
        emit("findings", round=rd, findings=fs, ruff=rf)
        history.append({"round": rd, "code": code, "findings": fs, "ruff": rf,
                        "done_reason": done_reason})

        if not fs and not rf:
            emit("done", reason="clean", round=rd, code=code)
            return history
        if rd == rounds - 1:
            emit("done", reason="max_rounds", round=rd, code=code)
            return history
        prompt = feedback_prompt(prompt, code, fs, rf)
    return history


# ---------------------------------------------------------------- 画面

def serve(port=8787, open_browser=True):
    import http.server, socketserver, threading, webbrowser

    # 配布の形によって置き場所が変わる（clone なら web/、wheel なら同梱先）
    page = next((q for q in (HERE / "web" / "loop.html",
                             HERE / "blindspot_assets" / "loop.html") if q.exists()), None)
    if page is None:
        print("画面のファイル loop.html が見つかりません。", file=sys.stderr)
        return 2

    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *a):
            pass                                   # 端末を汚さない

        def _send(self, code, ctype, body):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            if self.path in ("/", "/index.html"):
                self._send(200, "text/html; charset=utf-8",
                           page.read_bytes())
            elif self.path == "/api/models":
                self._send(200, "application/json; charset=utf-8",
                           json.dumps({"models": list_models()}).encode())
            else:
                self._send(404, "text/plain; charset=utf-8", b"not found")

        def do_POST(self):
            if self.path != "/api/run":
                self._send(404, "text/plain; charset=utf-8", b"not found")
                return
            n = int(self.headers.get("Content-Length", 0))
            try:
                req = json.loads(self.rfile.read(n).decode("utf-8"))
            except Exception:
                self._send(400, "text/plain; charset=utf-8", b"bad request")
                return

            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream; charset=utf-8")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "close")
            self.end_headers()

            def on_event(kind, payload):
                line = json.dumps({"kind": kind, **payload}, ensure_ascii=False)
                try:
                    self.wfile.write(b"data: " + line.encode("utf-8") + b"\n\n")
                    self.wfile.flush()
                except (BrokenPipeError, ConnectionResetError):
                    raise KeyboardInterrupt      # 画面を閉じられたら止める

            try:
                run_loop(req.get("task", ""), req.get("model", ""),
                         rounds=int(req.get("rounds", MAX_ROUNDS)),
                         use_ruff=bool(req.get("use_ruff", True)),
                         on_event=on_event)
            except KeyboardInterrupt:
                return
            except Exception as e:
                try:
                    on_event("error", message=f"{type(e).__name__}: {e}")
                except Exception:
                    pass
            self.close_connection = True

    class Server(socketserver.ThreadingTCPServer):
        allow_reuse_address = True
        daemon_threads = True

    url = f"http://127.0.0.1:{port}/"
    with Server(("127.0.0.1", port), Handler) as httpd:
        print(f"画面を開きました: {url}")
        print("止めるときは Control-C。")
        if not list_models():
            print("\n⚠ ollama が応答しません。別の端末で `ollama serve` を実行してください。")
        if open_browser:
            threading.Timer(0.5, lambda: webbrowser.open(url)).start()
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n終了します。")
    return 0


# ---------------------------------------------------------------- 端末

def _print_findings(fs, rf):
    for f in fs:
        print(f"    {f['rule']} {f['line']}行目: {f['message']}")
    for f in rf:
        print(f"    {f['rule']} {f['line']}行目: {f['message']}")


def run_cli(args):
    models = list_models()
    if not models:
        print("ollama が応答しません。`ollama serve` を実行してください。", file=sys.stderr)
        return 2
    model = args.model or ("qwen2.5-coder:7b" if "qwen2.5-coder:7b" in models
                           else models[0])
    if model not in models:
        print(f"{model} が見つかりません。入っているのは: {', '.join(models)}",
              file=sys.stderr)
        return 2

    state = {"rd": -1}

    def on_event(kind, p):
        if kind == "warmup":
            print(f"{p['model']} を読み込んでいます…", flush=True)
        elif kind == "round":
            state["rd"] = p["round"]
            label = "書かせています" if p["round"] == 0 else "差し戻して直させています"
            print(f"\n[{p['round'] + 1}回目] {label}…", flush=True)
        elif kind == "code":
            if p["code"] is None:
                print("  コードブロックが返りませんでした。", flush=True)
            else:
                note = "（上限で打ち切り）" if p["done_reason"] == "length" else ""
                print(f"  {p['wall_s']}秒{note}", flush=True)
        elif kind == "findings":
            n = len(p["findings"]) + len(p["ruff"])
            print(f"  検査: {n}件" if n else "  検査: 指摘なし", flush=True)
            _print_findings(p["findings"], p["ruff"])

    history = run_loop(args.task, model, rounds=args.rounds,
                       use_ruff=not args.no_ruff, on_event=on_event,
                       seed=args.seed)

    last = history[-1] if history else None
    if not last or not last["code"]:
        print("\nコードを取り出せませんでした。", file=sys.stderr)
        return 1
    clean = not last["findings"] and not last["ruff"]
    print("\n" + "-" * 60)
    print(last["code"].rstrip())
    print("-" * 60)
    if clean:
        print(f"{len(history)}回で検査器が黙りました。")
    else:
        print(f"{len(history)}回やっても指摘が残りました。自分で直してください。")
    print("※ 見ているのは blindspot の5項目と ruff の未定義名だけです。"
          "仕様どおり動くかは自分で確かめてください。")
    if args.out:
        pathlib.Path(args.out).write_text(last["code"], encoding="utf-8")
        print(f"{args.out} に書き出しました。")
    return 0 if clean else 1


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="blindspot-loop",
        description="ローカルLLMに書かせ、検査し、直るまで差し戻す。"
                    "引数なしで実行すると画面を開く。")
    ap.add_argument("task", nargs="?", help="やりたいことを書く")
    ap.add_argument("--model", "-m", help="使うモデル（既定 qwen2.5-coder:7b）")
    ap.add_argument("--rounds", "-r", type=int, default=MAX_ROUNDS,
                    help=f"差し戻しの上限回数（既定 {MAX_ROUNDS}）")
    ap.add_argument("--no-ruff", action="store_true",
                    help="ruff を併用しない（勧めません）")
    ap.add_argument("--seed", type=int, help="乱数種。同じ値なら同じ出力になる")
    ap.add_argument("--out", "-o", help="最終版を書き出すファイル")
    ap.add_argument("--port", type=int, default=8787, help="画面の待ち受けポート")
    ap.add_argument("--no-open", action="store_true", help="ブラウザを開かない")
    ap.add_argument("--models", action="store_true", help="使えるモデルを並べる")
    args = ap.parse_args(argv)

    if args.models:
        for m in list_models():
            print(m)
        return 0
    if args.task:
        return run_cli(args)
    return serve(port=args.port, open_browser=not args.no_open)


def cli():
    sys.exit(main())


if __name__ == "__main__":
    cli()

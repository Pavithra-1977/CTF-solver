"""
app.py — CTF Cryptography Solver · Flask Backend
=================================================
Run:  python app.py
Then open http://localhost:5000
"""

import os
import json
import time
from flask import Flask, render_template, request, Response, stream_with_context
from werkzeug.utils import secure_filename

import solver  # our local solver engine

# ─── Configuration ────────────────────────────────────────────────────────────
app = Flask(__name__)

app.config.update(
    UPLOAD_FOLDER=os.path.join(os.path.dirname(__file__), "uploads"),
    MAX_CONTENT_LENGTH=32 * 1024 * 1024,          # 32 MB upload limit
    # Default wordlist path — override via the UI or this constant
    DEFAULT_WORDLIST=os.environ.get(
        "WORDLIST_PATH",
        "/usr/share/wordlists/rockyou.txt"         # common Kali / ParrotOS path
    ),
    SECRET_KEY=os.urandom(24),
)

ALLOWED_EXTENSIONS = {
    "txt", "py", "pem", "enc", "json", "key", "pub",
    "bin", "dat", "crt", "der", "cap", "pcap",
}

os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)


# ─── Helpers ─────────────────────────────────────────────────────────────────

def allowed_file(filename: str) -> bool:
    return (
        "." in filename
        and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS
    )


def save_uploaded_files(file_list) -> list[str]:
    """Save werkzeug FileStorage objects; return list of saved paths."""
    saved = []
    for fobj in file_list:
        if fobj and fobj.filename and allowed_file(fobj.filename):
            fname = secure_filename(fobj.filename)
            dest = os.path.join(app.config["UPLOAD_FOLDER"], fname)
            fobj.save(dest)
            saved.append(dest)
    return saved


# ─── Routes ───────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html",
                           default_wordlist=app.config["DEFAULT_WORDLIST"])


@app.route("/solve", methods=["POST"])
def solve():
    """
    Accepts multipart/form-data:
      ciphertext   — raw text to analyse
      files        — one or more uploaded files
      flag_format  — e.g. 'flag{' or 'CTF{'
      wordlist     — path to rockyou or other wordlist

    Returns Server-Sent Events stream so the UI updates in real-time.
    Each SSE event is a JSON-encoded log entry or the final result.
    """
    # Pull form fields
    ciphertext   = request.form.get("ciphertext",   "").strip()
    flag_format  = request.form.get("flag_format",  "flag{").strip() or "flag{"
    wordlist     = request.form.get("wordlist",
                                    app.config["DEFAULT_WORDLIST"]).strip()

    # Save uploaded files
    uploaded_files = save_uploaded_files(request.files.getlist("files"))

    def _generate():
        """Run the solver and stream results as SSE."""
        try:
            result = solver.run_all_solvers(
                ciphertext, uploaded_files, flag_format, wordlist
            )
        except Exception as exc:
            import traceback
            err_result = {
                "flag_found": False,
                "flag": None,
                "method": None,
                "logs": [
                    solver.log_entry("error", "backend",
                                     f"Unhandled backend exception: {exc}\n{traceback.format_exc()}")
                ],
                "analysis": {"detected_types": [], "attempted_methods": []},
            }
            yield f"data: {json.dumps({'type': 'result', 'payload': err_result})}\n\n"
            return

        # Stream individual log entries first so the UI renders them live
        for entry in result.get("logs", []):
            yield f"data: {json.dumps({'type': 'log', 'payload': entry})}\n\n"

        # Final result event (without the logs blob to avoid duplication)
        final = {k: v for k, v in result.items() if k != "logs"}
        yield f"data: {json.dumps({'type': 'result', 'payload': final})}\n\n"

    return Response(
        stream_with_context(_generate()),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",   # disable nginx buffering if behind proxy
        },
    )


@app.route("/config")
def config_info():
    """Return current configuration as JSON (for debugging)."""
    return {
        "wordlist": app.config["DEFAULT_WORDLIST"],
        "wordlist_exists": os.path.isfile(app.config["DEFAULT_WORDLIST"]),
        "upload_folder": app.config["UPLOAD_FOLDER"],
        "pycrypto": solver.PYCRYPTO,
        "sympy": solver.SYMPY,
        "gmpy2": solver.GMPY2,
    }


# ─── Entry point ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 60)
    print("  CTF Cryptography Solver")
    print("  http://localhost:5000")
    print("=" * 60)
    print(f"  pycryptodome : {'✓' if solver.PYCRYPTO else '✗  (pip install pycryptodome)'}")
    print(f"  sympy        : {'✓' if solver.SYMPY   else '✗  (pip install sympy)'}")
    print(f"  gmpy2        : {'✓' if solver.GMPY2   else '✗  (optional, speeds up RSA math)'}")
    print(f"  Wordlist     : {app.config['DEFAULT_WORDLIST']}")
    print(f"    → exists   : {os.path.isfile(app.config['DEFAULT_WORDLIST'])}")
    print("=" * 60)
    app.run(debug=True, host="0.0.0.0", port=5000, threaded=True)

from pathlib import Path

ASSETS = Path(__file__).with_name("static")


def homepage() -> str:
    return (ASSETS / "index.html").read_text(encoding="utf-8")

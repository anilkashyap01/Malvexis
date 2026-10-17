from __future__ import annotations

from pathlib import Path

from jinja2 import Environment, PackageLoader

# autoescape=True is deliberate and mandatory: strings extracted from malware are attacker-controlled.
_env = Environment(loader=PackageLoader("malvexis.report", "templates"), autoescape=True, trim_blocks=True, lstrip_blocks=True)


def render_html(result: dict) -> str:
    return _env.get_template("report.html.j2").render(r=result)


def write_html(result: dict, path: str | Path) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_html(result), encoding="utf-8")
    return path

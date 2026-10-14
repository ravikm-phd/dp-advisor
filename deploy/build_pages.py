import argparse
import json
from pathlib import Path
from urllib.parse import urlsplit


SCRIPT_DIR = Path(__file__).resolve().parent
if (SCRIPT_DIR / "api" / "web").is_dir():
    SERVICE_DIR = SCRIPT_DIR / "api"
    REPOSITORY_DIR = SCRIPT_DIR.parent
else:
    SERVICE_DIR = SCRIPT_DIR
    REPOSITORY_DIR = SCRIPT_DIR.parent
ASSET_DIR_NAME = "dp-advisor-assets"


def main():
    parser = argparse.ArgumentParser(description="Build the GitHub Pages DP-Advice frontend.")
    parser.add_argument(
        "--api-base",
        default="https://dp-advice-api.onrender.com",
        help="Absolute URL of the deployed DP-Advice API.",
    )
    args = parser.parse_args()

    api_url = urlsplit(args.api_base.rstrip("/"))
    if api_url.scheme != "https" or not api_url.netloc:
        parser.error("--api-base must be an absolute HTTPS URL")

    web_dir = SERVICE_DIR / "web"
    html = (web_dir / "templates" / "index.html").read_text(encoding="utf-8")
    if 'href="/static/style.css"' not in html or 'src="/static/app.js"' not in html:
        raise SystemExit("Expected frontend asset references were not found in the template")

    html = html.replace(
        'href="/static/style.css"',
        f'href="/posts/{ASSET_DIR_NAME}/style.css"',
    )
    html = html.replace(
        'src="/static/app.js"',
        f'src="/posts/{ASSET_DIR_NAME}/app.js"',
    )
    html = html.replace(
        "</head>",
        f"<script>window.DP_ADVICE_API_BASE = {json.dumps(args.api_base.rstrip('/'))};</script>\n</head>",
    )

    output_assets = REPOSITORY_DIR / "posts" / ASSET_DIR_NAME
    output_assets.mkdir(parents=True, exist_ok=True)
    (REPOSITORY_DIR / "posts" / "dp-advisor.html").write_text(html, encoding="utf-8")
    for asset in ("app.js", "style.css"):
        content = (web_dir / "static" / asset).read_bytes()
        (output_assets / asset).write_bytes(content)

    print(f"Built {REPOSITORY_DIR / 'posts' / 'dp-advisor.html'}")
    print(f"Built frontend assets in {output_assets}")


if __name__ == "__main__":
    main()

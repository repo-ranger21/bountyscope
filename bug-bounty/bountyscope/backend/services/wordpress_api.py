import httpx
from typing import Optional


WP_API = "https://api.wordpress.org/plugins/info/1.2/"


async def fetch_plugin_info(slug: str) -> Optional[dict]:
    """
    Query the WordPress.org Plugin Info API for a given slug.
    Returns normalized plugin metadata or None if not found.
    """
    params = {
        "action": "plugin_information",
        "request[slug]": slug,
        "request[fields][active_installs]": "true",
        "request[fields][last_updated]": "true",
        "request[fields][versions]": "false",
        "request[fields][sections]": "false",
        "request[fields][screenshots]": "false",
        "request[fields][reviews]": "false",
        "request[fields][banners]": "false",
        "request[fields][icons]": "false",
    }

    async with httpx.AsyncClient(timeout=15) as client:
        try:
            resp = await client.get(WP_API, params=params)
            if resp.status_code != 200:
                return None

            data = resp.json()
            if isinstance(data, bool) or not data:
                return None

            return {
                "slug":           data.get("slug", slug),
                "name":           data.get("name", "Unknown"),
                "author":         _strip_html(data.get("author", "")),
                "version":        data.get("version", "unknown"),
                "last_updated":   data.get("last_updated", ""),
                "install_count":  data.get("active_installs", 0),
                "repo_status":    "active",
                "rating":         data.get("rating", 0),
                "num_ratings":    data.get("num_ratings", 0),
                "homepage":       data.get("homepage", ""),
                "requires":       data.get("requires", ""),
                "tested":         data.get("tested", ""),
                "download_link":  data.get("download_link", ""),
            }

        except (httpx.RequestError, ValueError, KeyError):
            return None


async def check_plugin_closed(slug: str) -> bool:
    """
    Attempt to detect if a plugin has been closed/delisted.
    WordPress returns a false-y body for closed plugins.
    """
    async with httpx.AsyncClient(timeout=10) as client:
        try:
            resp = await client.get(
                WP_API,
                params={"action": "plugin_information",
                        "request[slug]": slug},
            )
            body = resp.json()
            return isinstance(body, bool) and body is False
        except Exception:
            return False


def _strip_html(text: str) -> str:
    import re
    return re.sub(r"<[^>]+>", "", text).strip()

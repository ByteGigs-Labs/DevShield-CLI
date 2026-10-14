from __future__ import annotations

import json
import urllib.error
import urllib.request
from collections.abc import Callable
from typing import Any

from devshield import __version__

Transport = Callable[[str, dict[str, Any] | None], Any]
TIMEOUT_SECONDS = 30


class FetchError(Exception):
    pass


class NotFoundError(FetchError):
    pass


def http_transport(url: str, body: dict[str, Any] | None = None) -> Any:
    """GET (or POST when ``body`` is given) a JSON document over HTTPS."""
    if not url.startswith("https://"):
        raise FetchError(f"refusing non-HTTPS URL {url}")
    request = urllib.request.Request(  # noqa: S310 - the scheme is checked above
        url,
        data=None if body is None else json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json", "User-Agent": f"devshield/{__version__}"},
    )
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:  # noqa: S310
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            raise NotFoundError(f"{url}: not found") from exc
        raise FetchError(f"{url}: HTTP {exc.code}") from exc
    except (urllib.error.URLError, TimeoutError, ValueError, OSError) as exc:
        raise FetchError(f"{url}: {exc}") from exc

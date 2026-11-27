"""Bounded pagination using query values, never server-provided next URLs."""

from .client import ClientError, MAX_RESPONSE_BYTES, Response

# Scheme, default page size, and possible collection fields within data.
PAGINATED = {
    "prompts list": ("page", 20, ("prompts", "items")),
    "artifacts list": ("page", 25, ("artifacts", "items")),
    "submissions list": ("offset", 50, ("submissions", "items")),
    "detection-rules": ("after", 100, ("rules", "items")),
    "prompts indicators": ("before", 100, ("prompts", "items")),
    "taxii objects": ("taxii", 500, ("objects",)),
    "taxii manifest": ("taxii", 500, ("objects",)),
}
MISSING = object()


def integer(value, *, minimum=0):
    return isinstance(value, int) and not isinstance(value, bool) and value >= minimum


def next_query(command, payload, current):
    scheme, default_limit, fields = PAGINATED[command]
    if not isinstance(payload, dict):
        raise ClientError("Cannot paginate a non-object response")
    data = payload.get("data", payload)
    rows = data if isinstance(data, list) else None
    if isinstance(data, dict):
        rows = next((data[name] for name in fields if isinstance(data.get(name), list)), None)
    if rows is None:
        raise ClientError("Cannot locate the records in this paginated response")
    metadata = payload.get("pagination", data.get("pagination", {}) if isinstance(data, dict) else {})
    if not isinstance(metadata, dict):
        raise ClientError("Malformed pagination metadata")
    following = dict(current)

    if scheme in ("after", "before"):
        cursor = metadata.get("next", payload.get("next", data.get("next", MISSING) if isinstance(data, dict) else MISSING))
        if cursor is MISSING:
            if not rows:
                return None
            raise ClientError("Response omits the next cursor; cannot establish whether pagination is complete")
        if cursor is None:
            return None
        if scheme == "after":
            if not isinstance(cursor, str) or not cursor:
                raise ClientError("Expected a nonempty detection-rule cursor")
            following["after"] = cursor
        else:
            if not isinstance(cursor, dict) or any(not isinstance(cursor.get(key), str) or not cursor[key] for key in ("before", "before_id")):
                raise ClientError("Expected both before and before_id in the next prompt-indicator cursor")
            following.update({key: cursor[key] for key in ("before", "before_id")})
        return following

    if scheme == "taxii":
        if not isinstance(data, dict):
            raise ClientError("Expected a TAXII object envelope")
        more = data.get("more", False)
        if not isinstance(more, bool):
            raise ClientError("TAXII more must be a boolean")
        if not more:
            return None
        cursor = data.get("next")
        if not isinstance(cursor, str) or not cursor:
            raise ClientError("TAXII more=true requires a nonempty next cursor")
        following["next"] = cursor
        return following

    page_size = metadata.get("limit", current.get("limit", default_limit))
    if not integer(page_size, minimum=1):
        raise ClientError("Invalid pagination page size")
    position = current.get(scheme, 1 if scheme == "page" else 0)
    if not integer(position, minimum=1 if scheme == "page" else 0):
        raise ClientError("Invalid pagination position")
    more = metadata.get("has_more", metadata.get("hasMore", metadata.get("has_next", MISSING)))
    if more is not MISSING and not isinstance(more, bool):
        raise ClientError("Invalid pagination continuation flag")
    if more is False:
        return None
    if scheme == "page":
        page_next = metadata.get("next_page", MISSING)
        if page_next is None:
            return None
        if page_next is not MISSING:
            if not integer(page_next, minimum=position + 1):
                raise ClientError("The next page must advance the current page")
            following["page"] = page_next
            return following
        total_pages = metadata.get("total_pages", metadata.get("totalPages", MISSING))
        if total_pages is not MISSING:
            if not integer(total_pages):
                raise ClientError("Invalid total page count")
            if position >= total_pages:
                return None
            more = True
    total = metadata.get("total", metadata.get("total_count", MISSING))
    if total is not MISSING:
        if not integer(total):
            raise ClientError("Invalid total record count")
        consumed = position * page_size if scheme == "page" else position + len(rows)
        if consumed >= total:
            return None
        more = True
    if not rows:
        if more is True:
            raise ClientError("Pagination claims more records but returned an empty page")
        return None
    if more is MISSING and len(rows) < page_size:
        return None
    following[scheme] = position + (1 if scheme == "page" else len(rows))
    return following


def fetch_pages(client, endpoint, path, params, max_pages):
    pages, headers = [], []
    current = dict(params)
    seen = set()
    total_bytes = 0
    while True:
        state = tuple(sorted(current.items()))
        if state in seen:
            raise ClientError("Pagination cursor repeated; stopped before another request")
        seen.add(state)
        try:
            response = client.request("GET", path, service=endpoint.service, params=current,
                                      auth=endpoint.auth, label=endpoint.command)
            total_bytes += len(response.raw)
            if total_bytes > MAX_RESPONSE_BYTES:
                raise ClientError("Paginated responses exceed the 64 MiB aggregate client limit")
            following = next_query(endpoint.command, response.payload, current)
            if following is not None and tuple(sorted(following.items())) in seen:
                raise ClientError("Pagination cursor repeated; stopped before another request")
        except ClientError as exc:
            error = dict(exc.payload)
            error["pagination"] = {"pages_fetched": len(pages), "failed_query": current}
            raise ClientError(str(exc), code=exc.code, payload=client.redactor.value(error)) from exc
        pages.append(response.payload)
        headers.append(response.headers)
        if following is None or len(pages) >= max_pages:
            payload = {"pages": pages, "pagination": {"pages_fetched": len(pages), "max_pages": max_pages,
                       "complete": following is None, "stop_reason": "end" if following is None else "max_pages",
                       "next_query": following}}
            # Keep every original page envelope; never flatten away access/warning metadata.
            return Response(payload, b"", response.headers, response.status, "json"), headers
        current = following

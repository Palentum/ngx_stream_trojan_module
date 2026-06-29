from pathlib import Path

SRC = Path("ngx_stream_trojan_module.c").read_text()


def function_body(name: str) -> str:
    pos = SRC.index(f"\n{name}(") + 1
    start = SRC.index("{", pos)
    depth = 0
    for i in range(start, len(SRC)):
        ch = SRC[i]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return SRC[start:i + 1]
    raise AssertionError(f"function {name} body not found")


def assert_contains(haystack: str, needle: str) -> None:
    assert needle in haystack, f"missing {needle!r}"


# UDP DNS misses must allocate transient resolve state outside the connection
# pool and release it on every completion/cancel path. This catches the old
# monotonic c->pool growth path without needing a live nginx worker harness.
for name in (
    "ngx_stream_trojan_create_doh_resolve_data",
    "ngx_stream_trojan_start_resolver",
):
    body = function_body(name)
    assert_contains(body, "ngx_stream_trojan_resolve_pool(ctx, type)")

for name in (
    "ngx_stream_trojan_resolve_handler",
    "ngx_stream_trojan_doh_resolve_handler",
    "ngx_stream_trojan_finalize",
):
    body = function_body(name)
    assert_contains(body, "ngx_stream_trojan_destroy_resolve_data")

start_resolver = function_body("ngx_stream_trojan_start_resolver")
failure = start_resolver[start_resolver.index(
    "if (ngx_resolve_name(rctx) != NGX_OK)"
):]
failure = failure[:failure.index("return NGX_ERROR;")]
assert "ngx_resolve_name_done(rctx)" not in failure

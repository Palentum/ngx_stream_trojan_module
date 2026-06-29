from pathlib import Path

SRC = Path("ngx_stream_trojan_doh.c").read_text()


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


# DoH response headers can arrive one byte at a time.  The read handler must
# resume scanning at the saved cursor instead of rescanning the accumulated
# status/header line from the buffer start on each recv.
assert "size_t                       header_scan;" in SRC
assert "ngx_stream_trojan_doh_find_crlf" in SRC
assert "*scan = len - 1;" in SRC

handler = function_body("ngx_stream_trojan_doh_read_handler")
assert "ngx_stream_trojan_doh_find_crlf(doh->recv_buf" in handler
assert "ngx_stream_trojan_doh_find_crlf(line" in handler
assert "for (p = doh->recv_buf; p + 1 < end; p++)" not in handler
assert "for (p = line; p + 1 < end; p++)" not in handler
assert "doh->header_scan = 0;\n            doh->header_start = p + 2;" in handler
assert "doh->header_scan = 0;\n            line = p + 2;" in handler

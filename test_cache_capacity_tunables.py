from pathlib import Path

MODULE = Path("ngx_stream_trojan_module.c").read_text()
GEOSITE = Path("ngx_stream_trojan_geosite.c").read_text()


def assert_macro_overridable(src: str, name: str) -> None:
    guard = f"#ifndef {name}\n#define {name} "
    assert guard in src, f"{name} must be overridable with -D{name}=..."


def assert_has_sanity_check(src: str, name: str, ways: str) -> None:
    assert f"#if ({name} < {ways})" in src, f"{name} must reject values smaller than {ways}"
    assert f"({name} % {ways})" in src, f"{name} must reject values not divisible by {ways}"


for macro in (
    "NGX_STREAM_TROJAN_ROUTE_CACHE_ENTRIES",
    "NGX_STREAM_TROJAN_UDP_DOMAIN_CACHE_ENTRIES",
):
    assert_macro_overridable(MODULE, macro)
    assert_has_sanity_check(MODULE, macro, macro.replace("ENTRIES", "WAYS"))

assert_macro_overridable(
    GEOSITE, "NGX_STREAM_TROJAN_GEOSITE_CACHE_ENTRIES")
assert_has_sanity_check(
    GEOSITE,
    "NGX_STREAM_TROJAN_GEOSITE_CACHE_ENTRIES",
    "NGX_STREAM_TROJAN_GEOSITE_CACHE_WAYS",
)

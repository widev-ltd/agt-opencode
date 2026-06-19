# /// script
# requires-python = ">=3.9"
# dependencies = [
#     "jinja2==2.10",
# ]
# ///
"""Render a template — declares jinja2==2.10 via a PEP 723 inline metadata block.

This is the LIVE-track inline twin of the py-jinja2-2.10 requirements.txt fixture:
it exercises the SHIPPED resolveTransitive PEP-723 path (uv export --script) so the
Tier-2 scanner sees the FULL transitive set resolved from an INLINE block, not just
a requirements.txt. jinja2 2.10 carries known high/critical advisories (e.g.
CVE-2019-10906 sandbox escape) plus transitively-pulled MarkupSafe.
"""
from jinja2 import Template

print(Template("Hello {{ name }}").render(name="world"))

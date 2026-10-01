"""Every message that names an endpoint does so through a redaction helper — derived from the source.

The CLI sweep (``tests/cli/test_endpoint_secrets_never_printed.py``) runs the commands it can
drive to a network read; many ``fix: check that <endpoint> is reachable`` hints sit behind a
funded wallet or a mint in progress and are out of a subprocess test's reach. This scan covers
those, over every module under ``src/pyrxd``.

WHAT IT CHECKS. A *string-producing expression* is any of:

* an f-string (each interpolated value);
* ``"..." % x`` (the right operand), ``"...".format(...)`` and ``", ".join(...)`` (every argument);
* ``+`` with a string literal or f-string on either side (every other operand of the chain);
* a call to an OUTPUT SINK: ``click.echo`` / ``click.secho`` / ``print`` / ``warnings.warn``, any
  logging method (``debug`` … ``critical``, ``log``, ``warn``) on ANY receiver — ``logger``,
  ``self._log``, ``logging.getLogger(...)`` — and an exception constructor (a callee named
  ``…Error`` / ``…Exception``): every argument and keyword value, ``extra={...}`` included.

Inside one, a reference to a name or attribute that looks like an endpoint — ending in ``url`` /
``urls``, or starting with ``electrumx``, ``endpoint`` or ``node_rpc`` (leading underscores
ignored) — is a RAW SITE unless it sits inside a call to a redaction helper (:data:`_WRAPPERS`).
Any expression around the reference counts: ``f"{ctx.electrumx_url or None}"``, ``url[:20]``,
``str(url)`` and ``repr(endpoint)`` are all raw. The set of sites is derived by walking the AST,
not listed by hand; the non-vacuity assertion fails if the walk stops finding the wrapped ones.

WHAT IT CANNOT SEE (reviewed, not derived):

* SOURCE LABELS. ``glyph inspect`` / ``verify`` label every source with the raw endpoint URL
  (``label_a``, ``anchor_label``, ``binding_source`` …) because the source-identity rules compare
  them; those are redacted at RENDER time (``redact_endpoints_in``), not where each sentence is
  built, so a name-based rule cannot tell a raw label from a rendered one. They are covered by the
  CLI sweep's ``test_name_at_mark_source_labels_never_print_the_endpoint_secrets`` instead.
* A URL under a name that does not look like one (``target``, ``s``, ``value``), or one reached
  through a container (``cfg["electrumx"]`` is caught by the attribute name only when spelled as
  an attribute; a dict key is a string, not a name).
* A URL that flows into a string through a helper that is not a sink (``"".join([url])``,
  ``json.dumps({"u": url})``) and then into output by another name.
* Text pyrxd did not write (a library's exception) — that is ``redact_endpoint_secrets``'s job at
  each place such text is printed, and the CLI sweep's.
"""

from __future__ import annotations

import ast
import re
from collections.abc import Iterator
from pathlib import Path

import pytest

import pyrxd

SRC = Path(pyrxd.__file__).resolve().parent

#: A call to one of these renders an endpoint safely: scheme://host:port, a host, or scrubbed text.
_WRAPPERS = {
    "redacted_url",
    "redact_endpoint_secrets",
    "redact_endpoints_in",
    "endpoint_source_label",
    "describe_network_error",
    "canonical_host",
}
_LOG_METHODS = {"debug", "info", "warning", "warn", "error", "exception", "critical", "log"}
_PRINT_FUNCS = {"echo", "secho", "print"}
_ENDPOINT_NAME = re.compile(r"(urls?$|^electrumx|^endpoints?($|_)|^node_rpc)", re.IGNORECASE)


def _ident(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def _names_an_endpoint(node: ast.AST) -> bool:
    ident = _ident(node)
    return ident is not None and bool(_ENDPOINT_NAME.search(ident.lstrip("_")))


def _callee(node: ast.Call) -> str | None:
    return _ident(node.func)


def _is_wrapper(node: ast.AST) -> bool:
    return isinstance(node, ast.Call) and _callee(node) in _WRAPPERS


#: A call to one of these renders a number, a bool or a type — never the URL's text.
_NON_RENDERING_CALLS = {"len", "bool", "isinstance", "type", "id", "hash", "callable"}


def _refs(node: ast.AST) -> tuple[list[ast.AST], list[ast.AST]]:
    """``(raw, wrapped)`` endpoint references RENDERED by *node*. A reference under a wrapper call
    is wrapped; anything else — however it is combined, sliced or converted — is raw. Not rendered,
    so not counted: a comparison (renders a bool), ``len``/``isinstance``/``type``/… of it, the
    TEST of a conditional expression, and the object a plain field is read from (``endpoint.operator``
    renders the operator; ``endpoint.url`` is caught by its own name, ``url.strip()`` by its value)."""
    raw: list[ast.AST] = []
    wrapped: list[ast.AST] = []

    def visit(n: ast.AST, under_wrapper: bool, called: bool = False) -> None:
        if isinstance(n, ast.Compare) or (isinstance(n, ast.Call) and _callee(n) in _NON_RENDERING_CALLS):
            return
        if _is_wrapper(n):
            under_wrapper = True
        if _names_an_endpoint(n):
            (wrapped if under_wrapper else raw).append(n)
            return
        if isinstance(n, ast.IfExp):
            visit(n.body, under_wrapper)
            visit(n.orelse, under_wrapper)
            return
        if isinstance(n, (ast.ListComp, ast.SetComp, ast.GeneratorExp)):
            # `redacted_url(u) for u in urls` renders each element through the helper; the iterable
            # is wrapped exactly when the element is. `u for u in urls` leaves `urls` raw.
            elt_wrapped = any(_is_wrapper(x) for x in ast.walk(n.elt))
            visit(n.elt, under_wrapper)
            for gen in n.generators:
                visit(gen.iter, under_wrapper or elt_wrapped)
            return
        if isinstance(n, ast.Attribute) and not called:
            return  # a field read: what is rendered is the field, judged by its own name above
        if isinstance(n, ast.Call):
            visit(n.func, under_wrapper, called=True)
            for child in _call_operands(n):
                visit(child, under_wrapper)
            return
        for child in ast.iter_child_nodes(n):
            visit(child, under_wrapper)

    visit(node, False)
    return raw, wrapped


def _is_str_expr(node: ast.AST) -> bool:
    return isinstance(node, ast.JoinedStr) or (isinstance(node, ast.Constant) and isinstance(node.value, str))


def _flatten_add(node: ast.AST) -> list[ast.AST]:
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return _flatten_add(node.left) + _flatten_add(node.right)
    return [node]


def _call_operands(call: ast.Call) -> list[ast.AST]:
    out: list[ast.AST] = list(call.args)
    for kw in call.keywords:
        out.append(kw.value)
    return out


def _is_str_method(call: ast.Call) -> bool:
    """``"...".format(...)`` / ``"...".join(...)`` on a string literal or f-string."""
    f = call.func
    return isinstance(f, ast.Attribute) and f.attr in ("format", "join") and _is_str_expr(f.value)


def _is_sink(call: ast.Call) -> bool:
    name = _callee(call)
    if name is None:
        return False
    if name in _PRINT_FUNCS:
        return True
    if isinstance(call.func, ast.Attribute) and name in _LOG_METHODS:
        return True  # any receiver: logger, self._log, logging.getLogger(...), warnings
    return name.endswith(("Error", "Exception"))


def _url_constructions(tree: ast.AST) -> set[int]:
    """Nodes inside the value of an assignment TO an endpoint name (``url = f"{base}/api/tx"``,
    ``self._base_url = base_url + "/"``): that builds a URL, not a message. The result is itself an
    endpoint name, so where it is later printed the scan sees it by that name."""
    out: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Assign, ast.AnnAssign)) and node.value is not None:
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            if targets and all(_names_an_endpoint(t) for t in targets):
                out.update(id(n) for n in ast.walk(node.value))
    return out


def _message_operands(tree: ast.AST) -> Iterator[ast.AST]:
    """Every operand of every string-producing expression in *tree* (rule: module doc)."""
    skip = _url_constructions(tree)
    for node in ast.walk(tree):
        if id(node) in skip:
            continue
        if isinstance(node, ast.FormattedValue):
            yield node.value
        elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod) and _is_str_expr(node.left):
            yield node.right
        elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            parts = _flatten_add(node)
            if any(_is_str_expr(p) for p in parts):
                yield from (p for p in parts if not _is_str_expr(p))
        elif isinstance(node, ast.Call) and (_is_str_method(node) or _is_sink(node)):
            yield from _call_operands(node)


def _enclosing_functions(tree: ast.AST) -> dict[int, str]:
    out: dict[int, str] = {}
    for fn in ast.walk(tree):
        if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for n in ast.walk(fn):
                out[id(n)] = fn.name  # innermost wins: inner defs are walked after outer ones
    return out


def _sites_in(tree: ast.AST, rel: str) -> tuple[list[str], list[str]]:
    """``(raw, wrapped)`` as ``path:function:name@line`` (the exemption key is the part before ``@``)."""
    fns = _enclosing_functions(tree)
    raw: set[str] = set()
    wrapped: set[str] = set()
    for operand in _message_operands(tree):
        r, w = _refs(operand)
        raw.update(f"{rel}:{fns.get(id(n), '<module>')}:{_ident(n)}@{n.lineno}" for n in r)
        wrapped.update(f"{rel}:{fns.get(id(n), '<module>')}:{_ident(n)}@{n.lineno}" for n in w)
    return sorted(raw), sorted(wrapped)


def _sites() -> tuple[list[str], list[str]]:
    """``(raw sites, wrapped sites)`` over every module in ``src/pyrxd``."""
    raw: list[str] = []
    wrapped: list[str] = []
    for path in sorted(SRC.rglob("*.py")):
        r, w = _sites_in(ast.parse(path.read_text(encoding="utf-8")), str(path.relative_to(SRC)))
        raw += r
        wrapped += w
    return raw, wrapped


#: Raw sites that are not endpoint text, keyed ``path:function:name``. REVIEWED, NOT DERIVED — and
#: the membership is pinned below, so a new entry (or a stale one) forces a re-read of the reason.
_EXEMPT = {
    # The `pyrxd setup` config template writes the SHIPPED default endpoints into the new file.
    # Executable half: `test_the_shipped_defaults_the_template_writes_carry_no_credential`.
    "cli/config.py:write_default:url": "shipped defaults only, into a file the user owns",
    # A token's metadata image URL (from its own CBOR), shown by `glyph` commands — not an endpoint
    # pyrxd reads through, and no credential of the operator's.
    "cli/glyph_helpers.py:_metadata_summary:image_url": "token metadata, not an endpoint",
}


def test_no_message_names_an_endpoint_url_unredacted() -> None:
    raw, wrapped = _sites()
    by_key = {site.split("@", 1)[0] for site in raw}
    leftover = [site for site in raw if site.split("@", 1)[0] not in _EXEMPT]
    assert leftover == [], "endpoint URL in a message without a redaction helper:\n" + "\n".join(leftover)
    # Both directions: every exemption still matches a site (a stale one is a check that stopped).
    assert by_key == set(_EXEMPT), (by_key, set(_EXEMPT))
    # Non-vacuity: when this was widened (round 3) the walk found 111 wrapped sites across the CLI
    # f-strings, the failover and watchtower log lines and the registry/config messages, and the
    # two exempt raw sites. Far fewer wrapped sites means the walk broke, not that the code is clean.
    assert len(wrapped) >= 90, len(wrapped)


# Each shape the round-2 guard missed, as a snippet the scan must flag (and its wrapped twin must
# not). Planting these into a real module is the same check; here it runs on every test run.
_MISSED_SHAPES = [
    'f"{ctx.electrumx_url or None}"',
    'f"{url[:20]}"',
    '"%s" % url',
    '"{}".format(rpc_url)',
    '"endpoint " + url',
    'logging.getLogger(__name__).warning("failed on %s", endpoint.url)',
    'self._log.warning("x %s", node_rpc)',
    'logger.info("x", extra={"u": base_url})',
    "click.echo(url)",
    '", ".join(u for u in group_urls)',
    "print(electrumx_urls(ctx))",
    'raise ValidationError(f"insecure endpoint {url!r}")',
]


def test_every_shape_the_round_2_guard_missed_is_flagged() -> None:
    for snippet in _MISSED_SHAPES:
        raw, _ = _sites_in(ast.parse(snippet), "<snippet>")
        assert raw, f"not flagged: {snippet}"
        safe = re.sub(
            r"\b(ctx\.electrumx_url|url|rpc_url|endpoint\.url|node_rpc|base_url|group_urls|electrumx_urls\(ctx\))",
            r"redacted_url(\1)",
            snippet,
        )
        raw, wrapped = _sites_in(ast.parse(safe), "<snippet>")
        assert raw == [] and wrapped, f"wrapped form still flagged: {safe}"


def test_the_shipped_defaults_the_template_writes_carry_no_credential() -> None:
    """The executable half of the config-template exemption: every shipped endpoint is already its
    own redacted form (no user, password, path, query or fragment), so writing it raw leaks nothing."""
    from pyrxd.network.redaction import redacted_url
    from pyrxd.network.registry import default_endpoints

    shipped = [u for net in ("mainnet", "testnet", "regtest") for u in default_endpoints(net)]
    assert shipped, "no shipped endpoints — the check would be vacuous"
    for u in shipped:
        assert redacted_url(u) == u.rstrip("/"), u


def _registry_plaintext(u: str) -> None:
    from pyrxd.network.registry import Endpoint

    Endpoint(url=u.replace("wss://", "ws://"))  # plaintext without allow_insecure


def _registry_no_scheme(u: str) -> None:
    from pyrxd.network.registry import Endpoint

    Endpoint(url=u.split("://", 1)[1])  # `url.split(':')[0]` of `user:pw@host` is the user name


def _config_bad_operator(u: str) -> None:
    from pyrxd.cli.config import _as_endpoint_list

    _as_endpoint_list([{"url": u, "operator": ""}], "electrumx_servers")


def _config_two_operators(u: str) -> None:
    from pyrxd.cli.config import _as_endpoint_list

    _as_endpoint_list([{"url": u, "operator": "a"}, {"url": u, "operator": "b"}], "electrumx_servers")


@pytest.mark.parametrize(
    "build", [_registry_plaintext, _registry_no_scheme, _config_bad_operator, _config_two_operators]
)
def test_the_live_raw_sites_now_name_the_endpoint_redacted(build) -> None:
    """Round-3 F3: ``config.py`` (``{url!r}``, twice) and ``registry.py`` (``insecure endpoint
    {url!r}``, and the scheme check) were raw while the round-2 guard passed. Driven, not only
    scanned — and each must still say which endpoint, by host."""
    from pyrxd.security.errors import ValidationError

    url = "wss://USERSECRET1:PWSECRET22@h.example:50022/PATHSECRET333?k=QUERYSECRET4"
    with pytest.raises(ValidationError) as ei:
        build(url)
    text = str(ei.value)
    for secret in ("USERSECRET1", "PWSECRET22", "PATHSECRET333", "QUERYSECRET4"):
        assert secret not in text, text

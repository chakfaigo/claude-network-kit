"""Pure PF text generation/validation. No filesystem, process, or network actions."""

import shlex


ANCHOR_NAME = "local.claude-residential"
ANCHOR_FILE = "/etc/pf.anchors/" + ANCHOR_NAME
TUN_INTERFACE = "utun99"
BEGIN = "# BEGIN CLAUDE RESIDENTIAL GUARD"
END = "# END CLAUDE RESIDENTIAL GUARD"

_APPLE = (
    ('scrub-anchor', 'com.apple/*'),
    ('nat-anchor', 'com.apple/*'),
    ('rdr-anchor', 'com.apple/*'),
    ('dummynet-anchor', 'com.apple/*'),
    ('anchor', 'com.apple/*'),
    ('load', 'anchor', 'com.apple', 'from', '/etc/pf.anchors/com.apple'),
)
_GUARD = (
    ('anchor', ANCHOR_NAME),
    ('load', 'anchor', ANCHOR_NAME, 'from', ANCHOR_FILE),
)
GUARD_BLOCK = (
    f'{BEGIN}\nanchor "{ANCHOR_NAME}"\n'
    f'load anchor "{ANCHOR_NAME}" from "{ANCHOR_FILE}"\n{END}\n'
)


class UnsupportedPFConfig(ValueError):
    """The existing rules cannot be safely interpreted by this small installer."""


def _rows(text):
    if not isinstance(text, str) or "\x00" in text:
        raise UnsupportedPFConfig("PF 配置不是有效文本。")
    rows = []
    for number, line in enumerate(text.splitlines()):
        try:
            tokens = tuple(shlex.split(line, comments=True, posix=True))
        except ValueError as exc:
            raise UnsupportedPFConfig(f"PF 第 {number + 1} 行语法无法安全识别。") from exc
        if tokens:
            rows.append((number, tokens))
    return rows


def _has_guard(text):
    lines = text.splitlines()
    starts = [i for i, line in enumerate(lines) if line.strip() == BEGIN]
    ends = [i for i, line in enumerate(lines) if line.strip() == END]
    if not starts and not ends:
        return False
    if len(starts) != 1 or len(ends) != 1 or ends[0] != starts[0] + 3:
        raise UnsupportedPFConfig("PF 保护标记缺失、重复或不完整。")
    block = "\n".join(lines[starts[0]:ends[0] + 1]) + "\n"
    if block != GUARD_BLOCK:
        raise UnsupportedPFConfig("PF 保护块已被修改，停止自动合并。")
    return True


def validate_pf_conf(text, *, require_guard=True):
    """Accept only the known Apple baseline, optional loopback skip, and our block."""
    guarded = _has_guard(text)
    tokens = [value for _, value in _rows(text)]
    if tokens[:1] == [('set', 'skip', 'on', 'lo0')]:
        tokens.pop(0)
    expected = list(_APPLE[:4] + (_GUARD if guarded else ()) + _APPLE[4:])
    if tokens != expected:
        raise UnsupportedPFConfig(
            "PF 存在未知规则、非 lo0 skip、顺序变化或未经管理的保护引用；未修改网络。"
        )
    if require_guard and not guarded:
        raise UnsupportedPFConfig("PF 主配置没有本项目保护引用。")


def prepare_pf_conf(existing_text):
    """Insert once before Apple's filter anchor; preserve all unrelated source text."""
    validate_pf_conf(existing_text, require_guard=False)
    if _has_guard(existing_text):
        return existing_text
    rows = _rows(existing_text)
    line_number = next(number for number, tokens in rows if tokens == _APPLE[4])
    lines = existing_text.splitlines(keepends=True)
    result = "".join(lines[:line_number]) + GUARD_BLOCK + "".join(lines[line_number:])
    validate_pf_conf(result)
    return result


def render_anchor():
    """Allow rewritten TUN handshakes without creating states that can escape."""
    return (
        "# Ordinary traffic may leave only through this managed TUN.\n"
        "# mixed/system TCP rewrites tuples; its return SYN+ACK has no PF state.\n"
        "# The root proxy is trusted; DHCPv4 is a narrow link-control exception.\n"
        "pass out quick on lo0 all no state\n"
        f"pass out quick on {TUN_INTERFACE} all no state\n"
        "pass out quick proto { tcp, udp } from any to any user 0 keep state (if-bound)\n"
        "pass out quick inet proto udp from any port 68 to any port 67 no state\n"
        "block drop out quick all\n"
    )


def validate_anchor(text):
    """Do not accept widened interfaces, missing IPv6 block, or floating states."""
    actual = [tokens for _, tokens in _rows(text)]
    expected = [tokens for _, tokens in _rows(render_anchor())]
    if actual != expected:
        raise UnsupportedPFConfig("PF anchor 与受审查规则不一致。")


def validate_runtime_main_filter(text, *, require_guard=True):
    """Check normalized `pfctl -sr` main rules; refuse unfamiliar active rules."""
    anchors = []
    seen_filter = False
    seen_auxiliary = set()
    for _, tokens in _rows(text):
        scrub = tokens in {
            ('scrub-anchor', 'com.apple/*', 'all'),
            ('scrub-anchor', 'com.apple/*', 'all', 'fragment', 'reassemble'),
        }
        dummynet = tokens == ('dummynet-anchor', 'com.apple/*', 'all')
        # PF keeps normalization, filtering and dummynet in separate rulesets.
        # Display order of dummynet therefore does not alter filter precedence.
        if (scrub and not seen_filter) or dummynet:
            if tokens[0] in seen_auxiliary:
                raise UnsupportedPFConfig("实际 PF 辅助 anchor 重复，停止自动接管。")
            seen_auxiliary.add(tokens[0])
            continue
        if tokens[:1] != ('anchor',) or len(tokens) != 3 or tokens[2] != 'all':
            raise UnsupportedPFConfig("实际 PF 主规则含未知放行/过滤规则，停止自动接管。")
        seen_filter = True
        anchors.append(tokens[1])
    expected = [ANCHOR_NAME, 'com.apple/*'] if require_guard else ['com.apple/*']
    if anchors != expected:
        raise UnsupportedPFConfig("实际 PF anchor 缺失或执行顺序错误。")

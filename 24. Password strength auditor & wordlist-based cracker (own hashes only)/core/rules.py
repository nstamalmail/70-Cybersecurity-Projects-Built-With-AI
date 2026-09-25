"""hashcat-style rule engine (best64-compatible subset).

Rules are lines of operations applied left-to-right, mirroring hashcat
semantics for the operations we support (51 op forms). Unknown or malformed
rules fail closed: the line is skipped and a warning is recorded — never a
crash mid-run.

Supported forms (hashcat notation):
    :        (no-op)              l  lowercase            u  uppercase
    c        capitalize           C  lower-then-cap       t  toggle case
    T n      toggle pos n         d  duplicate            D n  delete pos n
    {        rotate left          }  rotate right
    $x       append char          ^x  prepend char
    [        drop first char      ]  drop last char
    sXY      substitute X->Y (all)
    @x       purge char x
    *xy      reject if contains x or y (condition; yields original on pass)
    z n      duplicate first char n times
    Z n      duplicate last char n times
    q        duplicate every char
    v        uppercase last char
    . n      shift mem right from pos n    , n  shift mem left from pos n
    y n      duplicate first block n       Y n  duplicate last block n
    +        increment last char ascii     -    decrement last char ascii
    i n X    insert char X at pos n        o n X  overwrite pos n with X
    ' n      truncate to n chars
    e        '1357' position uppercase
    E        title case (underscore/space/dot separators)
"""

from __future__ import annotations

from typing import Callable, List, Optional, Tuple

Op = Callable[[str], str]

_WARNINGS: List[str] = []


def warnings() -> List[str]:
    return list(_WARNINGS)


def reset_warnings() -> None:
    _WARNINGS.clear()


def _fail(line_no: int, rule: str, why: str) -> None:
    _WARNINGS.append(f"rule #{line_no + 1} '{rule}': {why} (skipped)")


def _rot_l(s: str) -> str:
    return s[1:] + s[0] if s else s


def _rot_r(s: str) -> str:
    return s[-1] + s[:-1] if s else s


def _toggle(s: str) -> str:
    return "".join(c.lower() if c.isupper() else c.upper() for c in s)


def _make_op(code: str, arg1: str, arg2: str) -> Optional[Op]:
    """Return a callable implementing one rule op, or None if malformed."""
    try:
        if code == ":":
            return lambda s: s
        if code == "l":
            return str.lower
        if code == "u":
            return str.upper
        if code == "c":
            return lambda s: (s[:1].upper() + s[1:]) if s else s
        if code == "C":
            return lambda s: (s[:1].lower() + s[1:].upper()) if s else s
        if code == "t":
            return _toggle
        if code == "T":
            n = int(arg1)
            return lambda s: (s[:n] + (s[n].lower() if s[n].isupper() else s[n].upper())
                              + s[n + 1:]) if 0 <= n < len(s) else s
        if code == "d":
            return lambda s: s + s
        if code == "D":
            n = int(arg1)
            return lambda s: s[:n] + s[n + 1:] if 0 <= n < len(s) else s
        if code == "{":
            return _rot_l
        if code == "}":
            return _rot_r
        if code == "$":
            if arg1 == "":
                return None
            return lambda s: s + arg1
        if code == "^":
            if arg1 == "":
                return None
            return lambda s: arg1 + s
        if code == "[":
            return lambda s: s[1:]
        if code == "]":
            return lambda s: s[:-1]
        if code == "s":
            if len(arg1) != 1 or len(arg2) != 1:
                return None
            x, y = arg1, arg2
            return lambda s: s.replace(x, y)
        if code == "@":
            if arg1 == "":
                return None
            x = arg1
            return lambda s: s.replace(x, "")
        if code == "*":
            if len(arg1) != 1 or len(arg2) != 1:
                return None
            x, y = arg1, arg2
            return lambda s: "" if (x in s or y in s) else s
        if code == "z":
            n = int(arg1)
            return lambda s: (s[:1] * n + s) if s else s
        if code == "Z":
            n = int(arg1)
            return lambda s: (s + s[-1:] * n) if s else s
        if code == "q":
            return lambda s: "".join(c + c for c in s)
        if code == "r":
            return lambda s: s[::-1]
        if code == "f":
            return lambda s: s + s[::-1]
        if code == "v":
            return lambda s: (s[:-1] + s[-1].upper()) if s else s
        if code == ".":
            n = int(arg1)
            def _shift_r(s: str, n: int = n) -> str:
                if not s or n <= 0 or n >= len(s):
                    return s
                mem = s[n - 1]
                return s[:n - 1] + mem + s[n - 1:-1]
            return _shift_r
        if code == ",":
            n = int(arg1)
            def _shift_l(s: str, n: int = n) -> str:
                if not s or n <= 0 or n >= len(s):
                    return s
                mem = s[len(s) - n]
                return s[1:] + mem
            return _shift_l
        if code == "y":
            n = int(arg1)
            return lambda s: (s[:n] + s) if 0 < n < len(s) else s
        if code == "Y":
            n = int(arg1)
            return lambda s: (s + s[-n:]) if 0 < n < len(s) else s
        if code == "+":
            return lambda s: (s[:-1] + chr((ord(s[-1]) + 1) % 256)) if s else s
        if code == "-":
            return lambda s: (s[:-1] + chr((ord(s[-1]) - 1) % 256)) if s else s
        if code == "i":
            n = int(arg1)
            if arg2 == "":
                return None
            return lambda s: (s[:n] + arg2 + s[n:]) if 0 <= n <= len(s) else s
        if code == "o":
            n = int(arg1)
            if arg2 == "":
                return None
            return lambda s: (s[:n] + arg2 + s[n + 1:]) if 0 <= n < len(s) else s
        if code == "'":
            n = int(arg1)
            return lambda s: s[:n]
        if code == "e":
            return lambda s: "".join(c.upper() if i in (1, 3, 5, 7) else c
                                     for i, c in enumerate(s))
        if code == "E":
            def _title(s: str) -> str:
                out, cap = [], True
                for c in s:
                    if c in "_-. ":
                        out.append(c)
                        cap = True
                    else:
                        out.append(c.upper() if cap else c.lower())
                        cap = False
                return "".join(out)
            return _title
    except ValueError:
        return None
    return None


def compile_rule(rule: str, line_no: int = 0) -> Tuple[List[Op], List[str]]:
    """Compile one rule line into a list of ops.

    Returns (ops, problems). Malformed tokens are dropped with a problem note;
    hashcat-style positional args are read greedily from the line.
    """
    ops: List[Op] = []
    problems: List[str] = []
    i, n = 0, len(rule)
    while i < n:
        c = rule[i]

        # Tokens that take a numeric argument.
        if c in "TDzZyY.,i o'":
            pass  # fallthrough handled below (spacing guard)

        if c == "s":
            if i + 2 < n:
                ops.append(_make_op("s", rule[i + 1], rule[i + 2]) or None)
                if not (ops and ops[-1]):
                    problems.append(f"s at {i}")
                    ops.pop()
                i += 3
                continue
            problems.append("s needs 2 chars")
            i += 1
            continue
        if c == "*":
            # hashcat-ish reject: *xy rejects if x or y present; *x rejects if x present.
            if i + 2 < n:
                op = _make_op("*", rule[i + 1], rule[i + 2])
                if op:
                    ops.append(op)
                    i += 3
                    continue
            if i + 1 < n:
                x = rule[i + 1]
                ops.append(lambda s, _x=x: "" if _x in s else s)
                i += 2
                continue
            problems.append("* needs a char")
            i += 1
            continue
        if c in ("$", "^", "@"):
            if i + 1 < n:
                op = _make_op(c, rule[i + 1], "")
                if op:
                    ops.append(op)
                else:
                    problems.append(f"{c} needs a char")
                i += 2
                continue
            problems.append(f"{c} needs a char")
            i += 1
            continue
        if c in ("i", "o"):
            if i + 2 < n and rule[i + 1].isdigit():
                op = _make_op(c, rule[i + 1], rule[i + 2])
                if op:
                    ops.append(op)
                else:
                    problems.append(f"{c} malformed")
                i += 3
                continue
            problems.append(f"{c} needs position+char")
            i += 1
            continue
        if c in "TDzZyY.,'":
            if i + 1 < n and rule[i + 1].isdigit():
                op = _make_op(c, rule[i + 1], "")
                if op:
                    ops.append(op)
                else:
                    problems.append(f"{c} malformed")
                i += 2
                continue
            problems.append(f"{c} needs a digit")
            i += 1
            continue
        if c in ":lucCtd{}[]qv+-eErf":
            op = _make_op(c, "", "")
            if op:
                ops.append(op)
            else:
                problems.append(f"op {c} unavailable")
            i += 1
            continue
        # Unknown token — fail closed.
        problems.append(f"unknown token '{c}'")
        i += 1

    return ops, problems


def parse_rules(text: str) -> Tuple[List[List[Op]], List[str]]:
    """Compile a rule file body. Comment (#) and blank lines are ignored."""
    compiled: List[List[Op]] = []
    problems: List[str] = []
    for ln, raw in enumerate(text.splitlines()):
        line = raw.rstrip("\r")
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        ops, probs = compile_rule(line, ln)
        for p in probs:
            problems.append(f"line {ln + 1}: {p}")
        if ops:
            compiled.append(ops)
    return compiled, problems


def apply_rule(word: str, ops: List[Op]) -> str:
    """Apply compiled ops left-to-right. Empty result means 'rejected'."""
    s = word
    for op in ops:
        if not s:
            return ""
        s = op(s)
    return s


def load_rules_file(path: str) -> Tuple[List[List[Op]], List[str]]:
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        return parse_rules(fh.read())

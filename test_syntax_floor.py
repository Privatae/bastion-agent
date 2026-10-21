"""Python 3.8 syntax floor for everything that runs on a member's machine.

bastion agent stages and the PII service ship to whatever the owner runs — a
Mac or Windows box may lag years behind Debian stable. The parser enforces
the floor (`feature_version`), and a short denylist covers stdlib calls
that parse fine on 3.8 and then fail at runtime. Add a directory here when
a new module joins the portable set. Run: python3 -m unittest discover .
"""

import ast
import os
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
PORTABLE = ("bastion_agent", "pii")
FLOOR = (3, 8)
BANNED_CALLS = ("removeprefix(", "removesuffix(", "file_digest(", "is_relative_to(",
                "zoneinfo", "bisect_left(", "pairwise(")  # bisect key= is 3.10


class SyntaxFloorTests(unittest.TestCase):
    def test_portable_modules_parse_at_floor(self):
        checked = 0
        for pkg in PORTABLE:
            for name in sorted(os.listdir(os.path.join(HERE, pkg))):
                if not name.endswith(".py"):
                    continue
                path = os.path.join(HERE, pkg, name)
                with open(path, encoding="utf-8") as fh:
                    src = fh.read()
                ast.parse(src, filename=path, feature_version=FLOOR)
                # PEP 585 generics (list[str]) parse on 3.8 but raise at
                # import time; catch them by inspection.
                for node in ast.walk(ast.parse(src)):
                    if isinstance(node, ast.Subscript) and isinstance(node.value, ast.Name) \
                            and node.value.id in ("list", "dict", "tuple", "set", "type"):
                        self.fail("%s: PEP 585 generic %s[...] needs typing.%s on 3.8"
                                  % (path, node.value.id, node.value.id.capitalize()))
                for banned in BANNED_CALLS:
                    self.assertNotIn(banned, src, "%s uses %s" % (path, banned))
                checked += 1
        self.assertGreater(checked, 5)


if __name__ == "__main__":
    unittest.main()

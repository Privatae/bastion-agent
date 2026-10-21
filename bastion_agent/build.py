"""Build the bastion agent distributable: one reproducible zipapp.

    python3 -m bastion_agent.build [--out dist]

Produces dist/bastion-agent-<version>.pyz and dist/bastion-agent-<version>.pyz.sha256.
The .pyz runs on any Python >= 3.8 on Mac, Windows or Linux:

    python3 bastion-agent-0.1.0.pyz doctor
    python3 bastion-agent-0.1.0.pyz sweep manifest.yaml

Inside: the `bastion_agent` package (no tests), the `pii` package (no tests,
no Dockerfile), and a vendored pure-Python PyYAML (MIT; the one import
the manifest loader needs that is not stdlib — the C accelerator is left
out on purpose so the same file runs everywhere). age and openssl stay
what they are: single external binaries `doctor` checks for. The repo's
`LICENSE` (GNU GPL v3 or later) is archived at the top level, so the
license travels with the program as GPL-3 sections 4 and 5 require.

Reproducible: fixed timestamps, sorted members, no bytecode, and the
vendored PyYAML pinned to one release (PYYAML_VERSION). Two builds of the
same tree are byte-identical on any machine, so the .sha256 means something
and anyone can rebuild a release and compare.
A native per-OS binary (PyInstaller/Nuitka) needs a build machine per OS
and is not produced here; this is the artifact until then.
"""

import argparse
import hashlib
import io
import os
import sys
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
TOOLS = os.path.dirname(HERE)
FIXED_TIME = (2026, 1, 1, 0, 0, 0)
SHEBANG = b"#!/usr/bin/env python3\n"

MAIN_SHIM = '''"""bastion agent zipapp entry point."""
import sys
from bastion_agent.__main__ import main
sys.exit(main())
'''

YAML_NOTICE = """PyYAML (vendored, pure-Python modules only)
License: MIT — Copyright (c) 2017-2021 Ingy döt Net, Copyright (c) 2006-2016 Kirill Simonov
https://github.com/yaml/pyyaml — the C accelerator (_yaml) is deliberately not included.
"""


def version():
    with open(os.path.join(HERE, "VERSION"), encoding="utf-8") as fh:
        return fh.read().strip()


def _package_files(src_dir, exclude_prefixes=("test_",), exclude_names=()):
    for name in sorted(os.listdir(src_dir)):
        if not name.endswith(".py") or name.startswith(exclude_prefixes) or name in exclude_names:
            continue
        with open(os.path.join(src_dir, name), "rb") as fh:
            yield name, fh.read()


# The PyYAML release that is vendored. Its source is copied in from whatever
# `import yaml` finds, so without a pin two machines with different PyYAML
# builds would make different .pyz files from the same tree. Move it on
# purpose, in its own commit.
PYYAML_VERSION = "6.0.3"


def _yaml_files():
    import yaml
    if getattr(yaml, "__version__", "") != PYYAML_VERSION:
        raise SystemExit(
            "build needs PyYAML %s to vendor (found %s at %s): pip install pyyaml==%s"
            % (PYYAML_VERSION, getattr(yaml, "__version__", "?"), yaml.__file__, PYYAML_VERSION))
    d = os.path.dirname(yaml.__file__)
    for name in sorted(os.listdir(d)):
        if name.endswith(".py"):
            with open(os.path.join(d, name), "rb") as fh:
                yield name, fh.read()


def members():
    """(arcname, bytes) for everything in the zipapp, deterministic order."""
    out = [("__main__.py", MAIN_SHIM.encode("utf-8"))]
    # build.py and verify_release.py are tools for making and checking a
    # release; neither is part of the program a bastion runs.
    for name, data in _package_files(HERE, exclude_names=("build.py", "verify_release.py")):
        out.append(("bastion_agent/" + name, data))
    with open(os.path.join(HERE, "VERSION"), "rb") as fh:
        out.append(("bastion_agent/VERSION", fh.read()))
    for name, data in _package_files(os.path.join(TOOLS, "pii")):
        out.append(("pii/" + name, data))
    for name, data in _yaml_files():
        out.append(("yaml/" + name, data))
    out.append(("yaml/LICENSE-NOTICE.txt", YAML_NOTICE.encode("utf-8")))
    with open(os.path.join(TOOLS, "LICENSE"), "rb") as fh:
        out.append(("LICENSE", fh.read()))
    return sorted(out, key=lambda m: m[0])


def build_bytes():
    buf = io.BytesIO()
    buf.write(SHEBANG)
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for arcname, data in members():
            info = zipfile.ZipInfo(arcname, date_time=FIXED_TIME)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            zf.writestr(info, data)
    return buf.getvalue()


def build(out_dir="dist"):
    os.makedirs(out_dir, exist_ok=True)
    data = build_bytes()
    ver = version()
    path = os.path.join(out_dir, "bastion-agent-%s.pyz" % ver)
    with open(path, "wb") as fh:
        fh.write(data)
    try:
        os.chmod(path, 0o755)
    except OSError:
        pass
    digest = hashlib.sha256(data).hexdigest()
    with open(path + ".sha256", "w", encoding="utf-8") as fh:
        fh.write("%s  %s\n" % (digest, os.path.basename(path)))
    return path, digest, len(data)


def main(argv=None):
    ap = argparse.ArgumentParser(prog="bastion_agent.build")
    ap.add_argument("--out", default="dist")
    args = ap.parse_args(argv)
    path, digest, size = build(args.out)
    print("%s  %d bytes  sha256 %s" % (path, size, digest))
    return 0


if __name__ == "__main__":
    sys.exit(main())

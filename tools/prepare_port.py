#!/usr/bin/env python3
"""Create the self-contained FreeBSD port overlaid into pfSense ports builds."""

from __future__ import annotations

import argparse
import shutil
from pathlib import Path


class PortError(RuntimeError):
    pass


def prepare_port(repo: Path, output: Path) -> Path:
    repo = repo.resolve()
    output = output.resolve()
    if output.exists():
        raise PortError(f"refusing to overwrite output: {output}")
    source_port = repo / "pfsense"
    modules = sorted((repo / "src" / "f2bguard").glob("*.py"))
    if not (source_port / "Makefile").is_file() or not modules:
        raise PortError("repository does not contain the port and Python modules")
    try:
        shutil.copytree(source_port, output)
        module_dir = output / "files/usr/local/share/f2bguard/f2bguard"
        module_dir.mkdir(parents=True)
        for module in modules:
            shutil.copyfile(module, module_dir / module.name)
        makefile = (output / "Makefile").read_text(encoding="utf-8")
        if "${FILESDIR}${DATADIR}/f2bguard/*.py" not in makefile:
            raise PortError("port Makefile does not install vendored Python modules from FILESDIR")
        if "../src" in makefile:
            raise PortError("generated port references files outside its port directory")
        return output
    except Exception:
        if output.exists():
            shutil.rmtree(output)
        raise


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        output = prepare_port(Path(__file__).resolve().parents[1], args.output)
    except (OSError, PortError) as exc:
        parser.error(str(exc))
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

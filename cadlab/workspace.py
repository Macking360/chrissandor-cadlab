from __future__ import annotations

import json
import math
import shutil
from pathlib import Path
from typing import List, Optional, Sequence

from . import APP_NAME, AUTHOR, VERSION
from . import geometry
from .log import AppLog
from .platform_support import IS_TERMUX, Layout, atomic_write, current_layout, initialize_layout, iso, utcnow, valid_name


class Workspace:
    def __init__(self, layout: Optional[Layout] = None):
        self.layout = initialize_layout(layout or current_layout())

    def project_dir(self, name: str) -> Path:
        return self.layout.dirs["projects"] / valid_name(name, "project name")

    def create_project(self, name: str) -> dict:
        target = self.project_dir(name)
        if target.exists():
            raise FileExistsError(f"Project already exists: {target}")
        (target / "parts").mkdir(parents=True)
        metadata = {"name": name, "created": iso(utcnow()), "author": AUTHOR, "application": APP_NAME, "version": VERSION}
        atomic_write(target / "project.json", json.dumps(metadata, indent=2).encode("utf-8"), 0o644)
        atomic_write(target / "README.txt", f"{APP_NAME} project: {name}\n".encode("utf-8"), 0o644)
        atomic_write(target / "parts.json", b"[]\n", 0o644)
        AppLog.logger.info("created project %s", target)
        return {"name": name, "path": str(target)}

    def list_projects(self) -> List[dict]:
        found = []
        for item in sorted(self.layout.dirs["projects"].glob("*/project.json")):
            try:
                data = json.loads(item.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                data = {"name": item.parent.name, "unreadable": True}
            sealed = (item.parent / ".cadlab-seal" / "manifest.json").exists()
            found.append({"name": data.get("name", item.parent.name), "path": str(item.parent), "sealed": sealed})
        return found

    def _require(self, project: str) -> Path:
        target = self.project_dir(project)
        if not (target / "project.json").exists():
            raise FileNotFoundError(f"No such project: {project}")
        return target

    def _register_part(self, target: Path, entry: dict) -> None:
        path = target / "parts.json"
        try:
            parts = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            parts = []
        parts = [p for p in parts if p.get("name") != entry["name"]] + [entry]
        atomic_write(path, (json.dumps(parts, indent=2) + "\n").encode("utf-8"), 0o644)

    def add_part(self, project: str, kind: str, name: str, dimensions: Sequence[float],
                 holes: Sequence[Sequence[float]] = (), segments: int = 48) -> dict:
        target = self._require(project)
        valid_name(name, "part name")
        files: List[str] = []
        entry = {"name": name, "type": kind, "created": iso(utcnow())}
        if kind == "box":
            if len(dimensions) != 3:
                raise ValueError("A box needs width, depth and height.")
            triangles = geometry.box_triangles(*[float(v) for v in dimensions])
            entry.update(dimensions=list(map(float, dimensions)), volume=geometry.signed_volume(triangles))
            atomic_write(target / "parts" / f"{name}.stl", geometry.stl_ascii(name, triangles).encode("ascii"), 0o644)
            files.append(f"parts/{name}.stl")
        elif kind == "cylinder":
            if len(dimensions) != 2:
                raise ValueError("A cylinder needs radius and height.")
            triangles = geometry.cylinder_triangles(float(dimensions[0]), float(dimensions[1]), int(segments))
            entry.update(dimensions=list(map(float, dimensions)), segments=int(segments),
                         volume=geometry.signed_volume(triangles))
            atomic_write(target / "parts" / f"{name}.stl", geometry.stl_ascii(name, triangles).encode("ascii"), 0o644)
            files.append(f"parts/{name}.stl")
        elif kind == "plate":
            if len(dimensions) != 2:
                raise ValueError("A plate needs width and depth.")
            width, depth = float(dimensions[0]), float(dimensions[1])
            hole_list = [tuple(float(v) for v in hole) for hole in holes]
            if any(len(h) != 3 for h in hole_list):
                raise ValueError("Each hole is x,y,diameter.")
            dxf, svg = geometry.plate_dxf(width, depth, hole_list), geometry.plate_svg(width, depth, hole_list)
            area = width * depth - sum(math.pi * (d / 2) ** 2 for _, _, d in hole_list)
            entry.update(dimensions=[width, depth], holes=[list(h) for h in hole_list], area=area)
            atomic_write(target / "parts" / f"{name}.dxf", dxf.encode("ascii"), 0o644)
            atomic_write(target / "parts" / f"{name}.svg", svg.encode("utf-8"), 0o644)
            files += [f"parts/{name}.dxf", f"parts/{name}.svg"]
        else:
            raise ValueError("Part type must be box, cylinder or plate.")
        entry["files"] = files
        self._register_part(target, entry)
        AppLog.logger.info("added %s part %s to %s", kind, name, project)
        return entry


def termux_guest_notes() -> List[str]:
    if not IS_TERMUX:
        return ["The PRoot helper is Termux-only. Linux, macOS and Windows use their native Python environment."]
    if not shutil.which("proot-distro"):
        return ["proot-distro is not installed. Run the setup command first."]
    return ["Ubuntu guest installation is a large download and uses device storage.",
            "Install it with: proot-distro install ubuntu",
            "Enter it with: proot-distro login ubuntu",
            "Inside Ubuntu: apt update && apt install -y python3 python3-venv python3-pip",
            "CadQuery wheel support varies by architecture and upstream release."]

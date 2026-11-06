import json
import math
from pathlib import Path

import pytest

from cadlab import geometry
from cadlab.workspace import Workspace


def test_box_is_a_closed_outward_solid():
    triangles = geometry.box_triangles(2, 3, 4)
    assert len(triangles) == 12
    assert geometry.signed_volume(triangles) == pytest.approx(24.0)


@pytest.mark.parametrize("segments", [3, 8, 48, 360])
def test_cylinder_volume_matches_polygon_formula(segments):
    triangles = geometry.cylinder_triangles(5, 10, segments)
    expected = 0.5 * segments * 25 * math.sin(2 * math.pi / segments) * 10
    assert len(triangles) == 4 * segments
    assert geometry.signed_volume(triangles) == pytest.approx(expected, rel=1e-9)


def test_stl_text_roundtrip_keeps_geometry():
    triangles = geometry.box_triangles(1.5, 2.5, 3.5)
    parsed = geometry.parse_stl_ascii(geometry.stl_ascii("t", triangles))
    assert len(parsed) == 12
    assert geometry.signed_volume(parsed) == pytest.approx(1.5 * 2.5 * 3.5, rel=1e-5)


def test_stl_normals_point_outward():
    text = geometry.stl_ascii("t", geometry.box_triangles(1, 1, 1))
    normals = [tuple(map(float, line.split()[2:5])) for line in text.splitlines() if line.strip().startswith("facet")]
    assert (0.0, 0.0, -1.0) in [tuple(round(c, 6) for c in n) for n in normals]
    assert (0.0, 0.0, 1.0) in [tuple(round(c, 6) for c in n) for n in normals]


@pytest.mark.parametrize("bad", [(0, 1, 1), (-1, 1, 1), (float("inf"), 1, 1), (float("nan"), 1, 1)])
def test_bad_box_dimensions(bad):
    with pytest.raises(ValueError):
        geometry.box_triangles(*bad)


def test_bad_cylinder_arguments():
    for args in ((0, 1, 8), (1, 0, 8), (1, 1, 2), (1, 1, 5000)):
        with pytest.raises(ValueError):
            geometry.cylinder_triangles(*args)


def test_plate_dxf_and_svg():
    holes = [(10, 10, 4), (30, 10, 4)]
    dxf = geometry.plate_dxf(40, 20, holes)
    assert geometry.parse_dxf_entities(dxf) == {"LINE": 4, "CIRCLE": 2}
    assert dxf.rstrip().endswith("EOF")
    svg = geometry.plate_svg(40, 20, holes)
    assert svg.count("<circle") == 2 and svg.startswith("<svg")


def test_hole_outside_plate_is_refused():
    with pytest.raises(ValueError):
        geometry.plate_dxf(10, 10, [(9, 5, 4)])
    with pytest.raises(ValueError):
        geometry.plate_dxf(10, 10, [(5, 5, -1)])


def test_project_and_part_files(layout):
    workspace = Workspace(layout)
    created = workspace.create_project("bracket")
    assert Path(created["path"], "project.json").exists()
    with pytest.raises(FileExistsError):
        workspace.create_project("bracket")
    box = workspace.add_part("bracket", "box", "base", [10, 10, 5])
    cyl = workspace.add_part("bracket", "cylinder", "post", [2, 8], segments=24)
    plate = workspace.add_part("bracket", "plate", "cover", [50, 30], holes=[[10, 10, 5]])
    assert box["volume"] == pytest.approx(500)
    assert cyl["volume"] == pytest.approx(0.5 * 24 * 4 * math.sin(2 * math.pi / 24) * 8)
    assert plate["area"] == pytest.approx(50 * 30 - math.pi * 2.5 ** 2)
    listed = json.loads(Path(created["path"], "parts.json").read_text(encoding="utf-8"))
    assert [p["name"] for p in listed] == ["base", "post", "cover"]
    assert {p["name"] for p in workspace.list_projects()} == {"bracket"}


def test_replacing_a_part_does_not_duplicate_it(layout):
    workspace = Workspace(layout)
    workspace.create_project("p1")
    workspace.add_part("p1", "box", "x", [1, 1, 1])
    workspace.add_part("p1", "box", "x", [2, 2, 2])
    parts = json.loads(Path(workspace.project_dir("p1"), "parts.json").read_text(encoding="utf-8"))
    assert len(parts) == 1 and parts[0]["volume"] == pytest.approx(8)


def test_part_argument_errors(layout):
    workspace = Workspace(layout)
    workspace.create_project("p2")
    with pytest.raises(ValueError):
        workspace.add_part("p2", "box", "x", [1, 2])
    with pytest.raises(ValueError):
        workspace.add_part("p2", "sphere", "x", [1])
    with pytest.raises(ValueError):
        workspace.add_part("p2", "box", "../x", [1, 1, 1])
    with pytest.raises(FileNotFoundError):
        workspace.add_part("missing", "box", "x", [1, 1, 1])


@pytest.mark.parametrize("bad", ["", "../x", "a b", ".git", "x" * 80])
def test_project_name_rules(layout, bad):
    with pytest.raises(ValueError):
        Workspace(layout).create_project(bad)

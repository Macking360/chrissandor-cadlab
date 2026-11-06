from __future__ import annotations

import math
from typing import List, Sequence, Tuple

Vec = Tuple[float, float, float]
Triangle = Tuple[Vec, Vec, Vec]


def _quad(a: Vec, b: Vec, c: Vec, d: Vec) -> List[Triangle]:
    return [(a, b, c), (a, c, d)]


def box_triangles(width: float, depth: float, height: float) -> List[Triangle]:
    for value in (width, depth, height):
        if not (value > 0 and math.isfinite(value)):
            raise ValueError("Dimensions must be positive numbers.")
    v = [(0.0, 0.0, 0.0), (width, 0.0, 0.0), (width, depth, 0.0), (0.0, depth, 0.0),
         (0.0, 0.0, height), (width, 0.0, height), (width, depth, height), (0.0, depth, height)]
    faces = [(0, 3, 2, 1), (4, 5, 6, 7), (0, 1, 5, 4), (2, 3, 7, 6), (3, 0, 4, 7), (1, 2, 6, 5)]
    triangles: List[Triangle] = []
    for a, b, c, d in faces:
        triangles += _quad(v[a], v[b], v[c], v[d])
    return triangles


def cylinder_triangles(radius: float, height: float, segments: int = 48) -> List[Triangle]:
    if not (radius > 0 and height > 0 and math.isfinite(radius) and math.isfinite(height)):
        raise ValueError("Radius and height must be positive numbers.")
    if not 3 <= segments <= 720:
        raise ValueError("Segments must be between 3 and 720.")
    ring = [(radius * math.cos(2 * math.pi * i / segments), radius * math.sin(2 * math.pi * i / segments))
            for i in range(segments)]
    bottom_center, top_center = (0.0, 0.0, 0.0), (0.0, 0.0, height)
    triangles: List[Triangle] = []
    for i in range(segments):
        (x1, y1), (x2, y2) = ring[i], ring[(i + 1) % segments]
        triangles.append((bottom_center, (x2, y2, 0.0), (x1, y1, 0.0)))
        triangles.append((top_center, (x1, y1, height), (x2, y2, height)))
        triangles += _quad((x1, y1, 0.0), (x2, y2, 0.0), (x2, y2, height), (x1, y1, height))
    return triangles


def _cross(a: Vec, b: Vec) -> Vec:
    return (a[1] * b[2] - a[2] * b[1], a[2] * b[0] - a[0] * b[2], a[0] * b[1] - a[1] * b[0])


def _sub(a: Vec, b: Vec) -> Vec:
    return (a[0] - b[0], a[1] - b[1], a[2] - b[2])


def signed_volume(triangles: Sequence[Triangle]) -> float:
    total = 0.0
    for a, b, c in triangles:
        cx = _cross(b, c)
        total += a[0] * cx[0] + a[1] * cx[1] + a[2] * cx[2]
    return total / 6.0


def stl_ascii(name: str, triangles: Sequence[Triangle]) -> str:
    lines = [f"solid {name}"]
    for a, b, c in triangles:
        n = _cross(_sub(b, a), _sub(c, a))
        length = math.sqrt(n[0] ** 2 + n[1] ** 2 + n[2] ** 2) or 1.0
        lines.append("  facet normal %.6e %.6e %.6e" % (n[0] / length, n[1] / length, n[2] / length))
        lines.append("    outer loop")
        for vertex in (a, b, c):
            lines.append("      vertex %.6e %.6e %.6e" % vertex)
        lines.append("    endloop")
        lines.append("  endfacet")
    lines.append(f"endsolid {name}")
    return "\n".join(lines) + "\n"


def parse_stl_ascii(text: str) -> List[Triangle]:
    vertices: List[Vec] = []
    for line in text.splitlines():
        parts = line.split()
        if parts and parts[0] == "vertex":
            vertices.append((float(parts[1]), float(parts[2]), float(parts[3])))
    if len(vertices) % 3:
        raise ValueError("Malformed STL: vertex count is not a multiple of three.")
    return [(vertices[i], vertices[i + 1], vertices[i + 2]) for i in range(0, len(vertices), 3)]


Hole = Tuple[float, float, float]


def _check_plate(width: float, depth: float, holes: Sequence[Hole]) -> None:
    if not (width > 0 and depth > 0):
        raise ValueError("Plate width and depth must be positive.")
    for x, y, diameter in holes:
        radius = diameter / 2
        if diameter <= 0:
            raise ValueError("Hole diameters must be positive.")
        if x - radius < 0 or y - radius < 0 or x + radius > width or y + radius > depth:
            raise ValueError(f"Hole at ({x}, {y}) with diameter {diameter} does not fit inside the plate.")


def plate_dxf(width: float, depth: float, holes: Sequence[Hole] = ()) -> str:
    _check_plate(width, depth, holes)
    out = ["0", "SECTION", "2", "ENTITIES"]
    corners = [(0, 0), (width, 0), (width, depth), (0, depth)]
    for i in range(4):
        (x1, y1), (x2, y2) = corners[i], corners[(i + 1) % 4]
        out += ["0", "LINE", "8", "OUTLINE", "10", repr(float(x1)), "20", repr(float(y1)), "30", "0.0",
                "11", repr(float(x2)), "21", repr(float(y2)), "31", "0.0"]
    for x, y, diameter in holes:
        out += ["0", "CIRCLE", "8", "HOLES", "10", repr(float(x)), "20", repr(float(y)), "30", "0.0",
                "40", repr(float(diameter) / 2)]
    out += ["0", "ENDSEC", "0", "EOF"]
    return "\n".join(out) + "\n"


def plate_svg(width: float, depth: float, holes: Sequence[Hole] = ()) -> str:
    _check_plate(width, depth, holes)
    pad = max(width, depth) * 0.05
    parts = [f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="{-pad:g} {-pad:g} {width + 2 * pad:g} {depth + 2 * pad:g}">',
             f'<rect x="0" y="0" width="{width:g}" height="{depth:g}" fill="none" stroke="black" stroke-width="{pad / 10:g}"/>']
    for x, y, diameter in holes:
        parts.append(f'<circle cx="{x:g}" cy="{depth - y:g}" r="{diameter / 2:g}" fill="none" stroke="black" stroke-width="{pad / 10:g}"/>')
    parts.append("</svg>")
    return "\n".join(parts) + "\n"


def parse_dxf_entities(text: str) -> dict:
    tokens = [line.strip() for line in text.splitlines()]
    counts: dict = {}
    for i in range(0, len(tokens) - 1, 2):
        if tokens[i] == "0" and tokens[i + 1] in ("LINE", "CIRCLE"):
            counts[tokens[i + 1]] = counts.get(tokens[i + 1], 0) + 1
    return counts

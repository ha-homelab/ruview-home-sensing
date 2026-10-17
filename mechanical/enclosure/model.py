"""Parametric RuView enclosure. Millimetres; +X antenna, -X USB, +Z lid.

Order-confirmed cable lengths do not certify the unmeasured clone PCB or RF
connector envelope. See README.md before printing or changing these profiles.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import zipfile
from dataclasses import asdict, dataclass
from pathlib import Path

import cadquery as cq
import trimesh

ROOT = Path(__file__).resolve().parent


@dataclass(frozen=True)
class Parameters:
    name: str
    pigtail_nominal_mm: float
    length: float
    width: float
    height: float
    board_length: float
    board_width: float
    board_thickness: float
    board_clearance_below: float
    sma_hole: float
    screw_pilot: float
    fit_clearance: float
    status: str

    def validate(self):
        if not (85 <= self.length <= 140 and 56 <= self.width <= 80):
            raise ValueError("Supported case envelope: L85–140, W56–80 mm")
        if not (22 <= self.height <= 32):
            raise ValueError("Supported body height: 22–32 mm")
        if not (55 <= self.board_length <= 68 and 24 <= self.board_width <= 30):
            raise ValueError("Board outside the supported removable-sled envelope")
        if not (0.25 <= self.fit_clearance <= 0.6):
            raise ValueError("Fit clearance must be 0.25–0.6 mm per side")
        if not (5.5 <= self.sma_hole <= 8 and 2.0 <= self.screw_pilot <= 2.8):
            raise ValueError("Connector or screw hole is outside supported range")
        if not (
            1 <= self.board_thickness <= 2 and 2 <= self.board_clearance_below <= 5
        ):
            raise ValueError("Unsupported PCB thickness or underside allowance")
        if (
            self.height - (6.4 + self.board_clearance_below + self.board_thickness + 7)
            < 3
        ):
            raise ValueError("Less than 3 mm above the reference component envelope")
        if self.length - self.board_length < 23:
            raise ValueError("Insufficient rear service bay")

    @property
    def board_x(self):
        return -self.length / 2 + 3.4 + self.board_length / 2

    @property
    def board_z(self):
        return 6.4 + self.board_clearance_below

    @property
    def sled_length(self):
        return self.board_length + 2

    @property
    def sled_width(self):
        return self.board_width + 8


def box(length, w, h, x=0, y=0, z=0):
    return (
        cq.Workplane("XY")
        .box(length, w, h, centered=(True, True, False))
        .translate((x, y, z))
    )


def rounded(length, w, h, r, x=0, y=0, z=0):
    return box(length, w, h, x, y, z).edges("|Z").fillet(r)


def cylinder(radius, h, x=0, y=0, z=0):
    return cq.Workplane("XY").circle(radius).extrude(h).translate((x, y, z))


def xhole(diameter, depth, x, y, z):
    return cq.Workplane("YZ").circle(diameter / 2).extrude(depth).translate((x, y, z))


def fasteners(p):
    return [
        (sx * (p.length / 2 - 6), sy * (p.width / 2 - 6))
        for sx in (-1, 1)
        for sy in (-1, 1)
    ]


def sled_corners(p):
    return [
        (p.board_x + sx * (p.sled_length / 2 - 2), sy * (p.sled_width / 2 - 1.8))
        for sx in (-1, 1)
        for sy in (-1, 1)
    ]


def make_base(p, wall_tabs=False):
    part = rounded(p.length, p.width, p.height, 6)
    part = part.cut(rounded(p.length - 4.8, p.width - 4.8, p.height, 3.6, z=2.4))
    for x, y in fasteners(p):
        part = part.union(cylinder(4.4, p.height - 2.4, x, y, 2.4))
        part = part.cut(cylinder(p.screw_pilot / 2, 13, x, y, p.height - 12))
    # Top-open USB window avoids a long FDM bridge; lid completes its roof.
    part = part.cut(box(8, p.board_width + 6, p.height, -p.length / 2, z=7.4))
    # Top-loaded antenna panel: front tongue, inner flange, retaining rails.
    part = part.cut(box(8, 20 + 2 * p.fit_clearance, p.height, p.length / 2, z=5.6))
    for sy in (-1, 1):
        part = part.union(
            box(3.8, 3.1, p.height - 4, p.length / 2 - 4.3, sy * 13.95, 4)
        )
        part = part.union(
            box(1.4, 5.9, p.height - 4, p.length / 2 - 5.5, sy * 12.55, 4)
        )
    # Four shelves locate a removable sled; ties run below it.
    for x, y in sled_corners(p):
        part = part.union(box(3.6, 3.2, 2, x, y, 2.4))
        sy = 1 if y > 0 else -1
        part = part.union(
            box(4, 1.4, 4.4, x, sy * (p.sled_width / 2 + p.fit_clearance + 0.7), 2.4)
        )
        sx = 1 if x > p.board_x else -1
        part = part.union(
            box(
                1.4,
                3.2,
                4.4,
                p.board_x + sx * (p.sled_length / 2 + p.fit_clearance + 0.7),
                y,
                2.4,
            )
        )
    # Tie eyelets keep a loose RF service loop off the lid and PCB antenna.
    for sy in (-1, 1):
        eye = box(5, 4, 7, p.length / 2 - 12, sy * 18.5, 2.4)
        hole = (
            cq.Workplane("XZ")
            .circle(1.5)
            .extrude(8, both=True)
            .translate((p.length / 2 - 12, sy * 18.5, 6.2))
        )
        part = part.union(eye.cut(hole))
    # Small side vents bridge only 6 mm in the stated print orientation.
    for sy in (-1, 1):
        for i in range(4):
            part = part.cut(
                box(6, 8, 2.4, -p.length / 2 + 19 + i * 11, sy * p.width / 2, 16)
            )
    if wall_tabs:
        for x in (-p.length / 2 + 17, p.length / 2 - 17):
            ear = rounded(13, 16, 3, 3, x, p.width / 2 + 2)
            ear = ear.cut(cylinder(2, 5, x, p.width / 2 + 5, -1))
            part = part.union(ear)
    return part.clean()


def make_sled(p):
    part = rounded(p.sled_length, p.sled_width, 2, 1.2, p.board_x, z=4.4)
    for sy in (-1, 1):
        part = part.cut(
            rounded(
                p.board_length - 14,
                1.8,
                4,
                0.7,
                p.board_x - 1,
                sy * (p.board_width / 2 + 2.1),
                3.4,
            )
        )
    # No fixed PCB holes or assumed component-contact ledges.
    return part.clean()


def make_lid(p):
    part = rounded(p.length, p.width, 2.4, 6, z=p.height)
    for x, y in fasteners(p):
        part = part.cut(cylinder(1.6, 5, x, y, p.height - 1))
    for x, y in sled_corners(p):
        part = part.union(box(3, 2.4, p.height - 6.8, x, y, 6.8))
    for sy in (-1, 1):
        part = part.union(
            box(18, 1.6, 1.8, 0, sy * (p.width / 2 - 3.6), p.height - 1.8)
        )
    x = -p.length / 2 + 15
    while x < p.length / 2 - 17:
        part = part.cut(rounded(2.4, 11, 4, 1, x, 6, p.height - 0.5))
        x += 6
    text = (
        cq.Workplane("XY")
        .text("RuView", 7, 0.6, combine=False)
        .translate((0, -10, p.height + 1.9))
    )
    part = part.cut(text)
    return part.clean()


def make_panel(p, blank=False):
    # Outer face is recessed by 0.4 mm. The bulkhead sees only 2.4 mm plastic.
    top = p.height - 0.3
    part = box(2.4, 20, top - 6, p.length / 2 - 1.6, z=6)
    # The flange expands at 45 degrees when printed outer face down.
    # A square stepped flange would introduce a 2 mm unsupported cantilever.
    flange = (
        cq.Workplane("YZ", origin=(p.length / 2 - 2.8, 0, (top + 6) / 2))
        .rect(20, top - 6)
        .workplane(offset=-1.6)
        .center(0, -0.8)
        .rect(23.2, top - 4.4)
        .loft(combine=True)
    )
    flange = flange.cut(xhole(16, 3, p.length / 2 - 5, 0, 14.2))
    part = part.union(flange)
    if not blank:
        part = part.cut(xhole(p.sma_hole, 8, p.length / 2 - 7, 0, 14.2))
    return part.clean()


def make_coupon(p):
    part = rounded(65, 27, 2.4, 2)
    for x, d in zip((-23, -8, 7), (6.2, 6.6, 7.0), strict=True):
        part = part.cut(cylinder(d / 2, 4, x, 5, -0.5))
        label = (
            cq.Workplane("XY")
            .text(str(d), 3.5, 0.5, combine=False)
            .translate((x, -4, 2))
        )
        part = part.cut(label)
    for y, d in zip((-7, 0, 7), (2.2, 2.4, 2.6), strict=True):
        part = part.cut(cylinder(d / 2, 4, 24, y, -0.5))
    return part.clean()


def components(p):
    p.validate()
    return {
        "base": make_base(p),
        "base-wall": make_base(p, True),
        "lid": make_lid(p),
        "sled": make_sled(p),
        "panel-sma": make_panel(p),
        "panel-blank": make_panel(p, True),
        "spacer": rounded(5, 5, p.board_clearance_below - 1, 0.6),
        "fit-coupon": make_coupon(p),
    }


def print_pose(name, part):
    if name == "lid":
        part = part.rotate((0, 0, 0), (1, 0, 0), 180)
    if name.startswith("panel"):
        # Flat outer face on the bed; flange grows upward, no supports.
        part = part.rotate((0, 0, 0), (0, 1, 0), 90)
    b = part.val().BoundingBox()
    return part.translate((-(b.xmin + b.xmax) / 2, -(b.ymin + b.ymax) / 2, -b.zmin))


def reference_board(p):
    return box(p.board_length, p.board_width, p.board_thickness, p.board_x, z=p.board_z)


def validate_assembly(p, parts):
    names = ("base", "lid", "sled", "panel-sma")
    checks = {}
    for i, a in enumerate(names):
        for b in names[i + 1 :]:
            vol = parts[a].intersect(parts[b]).val().Volume()
            checks[f"{a}/{b}"] = round(vol, 8)
            if vol > 0.00001:
                raise ValueError(f"Assembly collision: {a}/{b}: {vol} mm³")
    board = reference_board(p)
    for name in names:
        vol = parts[name].intersect(board).val().Volume()
        checks[f"{name}/reference-pcb"] = round(vol, 8)
        if vol > 0.00001:
            raise ValueError(f"Reference PCB collision with {name}: {vol} mm³")
    return checks


def generate(profile, output):
    p = Parameters(**json.loads(profile.read_text()))
    parts = components(p)
    collisions = validate_assembly(p, parts)
    output.mkdir(parents=True, exist_ok=True)
    report = {
        "profile": asdict(p),
        "units": "mm",
        "physical_fit_verified": False,
        "source_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "profile_sha256": hashlib.sha256(profile.read_bytes()).hexdigest(),
        "cadquery_version": cq.__version__,
        "nominal_wall_mm": 2.4,
        "collision_volume_mm3": collisions,
        "parts": {},
    }
    for name, part in parts.items():
        if not part.val().isValid() or len(part.solids().vals()) != 1:
            raise ValueError(f"{name}: expected one valid CAD solid")
        pose = print_pose(name, part)
        path = output / f"{name}.stl"
        cq.exporters.export(pose, str(path), tolerance=0.035, angularTolerance=0.12)
        cq.exporters.export(pose, str(output / f"{name}.step"))
        mesh = trimesh.load_mesh(path)
        if not mesh.is_watertight or not mesh.is_winding_consistent or mesh.volume <= 0:
            raise ValueError(f"{name}: STL is not a closed outward-facing volume")
        if mesh.body_count != 1:
            raise ValueError(f"{name}: disconnected mesh")
        report["parts"][name] = {
            "bounds_mm": mesh.extents.round(3).tolist(),
            "volume_mm3": round(mesh.volume, 3),
            "triangles": len(mesh.faces),
            "watertight": True,
            "cad_valid": True,
            "body_count": 1,
            "stl_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        }
    assembly = cq.Assembly(name=p.name)
    for name, color in (
        ("base", "#24374d"),
        ("lid", "#42bfc0"),
        ("sled", "#ffbe69"),
        ("panel-sma", "#ffbe69"),
    ):
        rgb = tuple(int(color[i : i + 2], 16) / 255 for i in (1, 3, 5))
        assembly.add(parts[name], name=name, color=cq.Color(*rgb))
    assembly.add(
        reference_board(p),
        name="REFERENCE_PCB_DO_NOT_PRINT",
        color=cq.Color(0.16, 0.49, 0.32),
    )
    assembly.export(str(output / "assembly.step"))
    (output / "validation.json").write_text(json.dumps(report, indent=2) + "\n")
    with zipfile.ZipFile(
        output / "print-pack.zip", "w", zipfile.ZIP_DEFLATED
    ) as bundle:
        files = sorted(output.glob("*.stl")) + [
            output / "assembly.step",
            output / "validation.json",
        ]
        contents = {path.name: path.read_bytes() for path in files}
        contents["READ-FIRST.txt"] = (
            "FIRST-FIT PROTOTYPE. All units are mm; import STL at 100% scale.\n"
            "Print the coupon and sled before a complete case.\n"
            "Choose base OR base-wall, lid, sled, panel-sma OR panel-blank, and 4 spacers.\n"
            "assembly.step contains a reference PCB; do not print the whole assembly.\n"
            "Full instructions: https://github.com/ha-homelab/ruview-home-sensing/blob/"
            "main/mechanical/enclosure/README.md\n"
        ).encode()
        for name, data in sorted(contents.items()):
            info = zipfile.ZipInfo(f"{p.name}/{name}", (2026, 10, 16, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            bundle.writestr(info, data)
    return p, parts, report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", type=Path)
    parser.add_argument("--output", type=Path, default=ROOT / "generated")
    args = parser.parse_args()
    profiles = (
        [args.profile] if args.profile else sorted((ROOT / "profiles").glob("*.json"))
    )
    for profile in profiles:
        _, _, report = generate(profile, args.output / profile.stem)
        print(f"{profile.stem}: {len(report['parts'])} closed solids; assembly clear")


if __name__ == "__main__":
    main()

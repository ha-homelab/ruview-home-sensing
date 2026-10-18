"""Render the actual CAD solids and dimensioned plan, without a browser."""

from __future__ import annotations

import json
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import vtk
from matplotlib.colors import to_rgb
from matplotlib.patches import Circle, FancyBboxPatch, Rectangle
from model import Parameters, box, components, cylinder, reference_board
from vtk.util.numpy_support import vtk_to_numpy

ROOT = Path(__file__).resolve().parent
BG = "#f5f7fa"
INK = "#192a3e"
COLORS = {
    "base": "#3a5773",
    "lid": "#2cb9b5",
    "sled": "#ffc071",
    "panel-sma": "#f6ae54",
}


def add(ax, part, color, shift=(0, 0, 0)):
    vertices, triangles = part.val().tessellate(0.12, 0.18)
    v = np.array([v.toTuple() for v in vertices]) + shift
    points = vtk.vtkPoints()
    for point in v:
        points.InsertNextPoint(*point)
    cells = vtk.vtkCellArray()
    for triangle in triangles:
        cells.InsertNextCell(3, triangle)
    poly = vtk.vtkPolyData()
    poly.SetPoints(points)
    poly.SetPolys(cells)
    normals = vtk.vtkPolyDataNormals()
    normals.SetInputData(poly)
    normals.ConsistencyOn()
    normals.AutoOrientNormalsOn()
    normals.SetFeatureAngle(45)
    mapper = vtk.vtkPolyDataMapper()
    mapper.SetInputConnection(normals.GetOutputPort())
    actor = vtk.vtkActor()
    actor.SetMapper(mapper)
    actor.GetProperty().SetColor(*to_rgb(color))
    actor.GetProperty().SetAmbient(0.3)
    actor.GetProperty().SetDiffuse(0.7)
    actor.GetProperty().SetSpecular(0.15)
    actor.GetProperty().SetSpecularPower(35)
    ax.AddActor(actor)


def setup(ax, p, zmax=80, xmax=None):
    ax.SetBackground(*to_rgb(BG))
    camera = ax.GetActiveCamera()
    camera.SetPosition(145, -190, 145)
    camera.SetFocalPoint(5, 0, zmax / 2)
    camera.SetViewUp(0, 0, 1)
    camera.ParallelProjectionOn()
    camera.SetParallelScale(62)


def render_scene(renderer):
    window = vtk.vtkRenderWindow()
    window.SetOffScreenRendering(1)
    window.SetMultiSamples(8)
    window.SetSize(1150, 850)
    window.AddRenderer(renderer)
    renderer.ResetCameraClippingRange()
    window.Render()
    capture = vtk.vtkWindowToImageFilter()
    capture.SetInput(window)
    capture.ReadFrontBufferOff()
    capture.Update()
    array = vtk_to_numpy(capture.GetOutput().GetPointData().GetScalars())
    result = array.reshape(850, 1150, 3)[::-1].copy()
    window.Finalize()
    return result


def pcb(ax, p, shift=(0, 0, 0)):
    add(ax, reference_board(p), "#30866a", shift)
    # Illustrative electronics: board outline is the nominal mechanical envelope.
    end = p.board_x + p.board_length / 2
    add(ax, box(18, 18, 3, end - 16, z=p.board_z + p.board_thickness), "#becbd2", shift)
    for y in (-6.0, 6.0):
        add(
            ax,
            box(
                7,
                8.7,
                3.3,
                p.board_x - p.board_length / 2 + 3,
                y,
                p.board_z + p.board_thickness,
            ),
            "#c1cad0",
            shift,
        )


def main():
    p = Parameters(**json.loads((ROOT / "profiles/pigtail-80.json").read_text()))
    parts = components(p)
    images = ROOT / "images"
    images.mkdir(exist_ok=True)
    fig = plt.figure(figsize=(15, 8), facecolor=BG)
    fig.text(0.06, 0.93, "RuView / S3 enclosure", color=INK, size=27, weight="bold")
    fig.text(
        0.06,
        0.88,
        "Three cable-length variants. Replaceable SMA panel. Removable board sled.",
        color="#536b80",
        size=13,
    )
    left = vtk.vtkRenderer()
    setup(left, p, 70, p.length / 2 + 40)
    for name in ("base", "lid", "panel-sma"):
        add(left, parts[name], COLORS[name])
    # Short representative hinged antenna, deliberately not a measured product model.
    sma = (
        cylinder(3, 12)
        .rotate((0, 0, 0), (0, 1, 0), 90)
        .translate((p.length / 2 - 1, 0, 14.2))
    )
    add(left, sma, "#c2a064")
    add(left, cylinder(4.8, 49, p.length / 2 + 13, 0, 14.2), "#24303d")
    fig.text(0.07, 0.23, "01  CLOSED", size=12, color=INK, weight="bold")
    fig.text(
        0.07,
        0.19,
        "105 × 58 × 26.4 mm body · 80 mm cable variant",
        size=11,
        color="#536b80",
    )
    left_plot = fig.add_axes((0.02, 0.25, 0.45, 0.58))
    left_plot.imshow(render_scene(left))
    left_plot.axis("off")
    right = vtk.vtkRenderer()
    setup(right, p, 80)
    add(right, parts["base"], COLORS["base"])
    add(right, parts["sled"], COLORS["sled"], (0, 0, 9))
    pcb(right, p, (0, 0, 13))
    add(right, parts["panel-sma"], COLORS["panel-sma"], (6, 0, 11))
    add(right, parts["lid"], COLORS["lid"], (0, 0, 37))
    right_plot = fig.add_axes((0.47, 0.25, 0.52, 0.60))
    right_plot.imshow(render_scene(right))
    right_plot.axis("off")
    fig.text(0.55, 0.23, "02  SERVICEABLE", size=12, color=INK, weight="bold")
    fig.text(
        0.55,
        0.19,
        "Four screws · open USB end · interchangeable antenna insert",
        size=11,
        color="#536b80",
    )
    fig.text(
        0.06,
        0.10,
        "STL + STEP + editable CadQuery source",
        size=14,
        color="#188783",
        weight="bold",
    )
    fig.text(
        0.06,
        0.055,
        "FIT PROTOTYPE  /  Actual printed-part CAD; electronics and shortened antenna are illustrative. Physical fit and RF tests pending.",
        size=10,
        color="#6a7989",
    )
    fig.savefig(images / "enclosure-preview.png", dpi=160, facecolor=BG)
    plt.close(fig)

    fig, ax = plt.subplots(figsize=(13, 8), facecolor=BG)
    ax.set_facecolor(BG)
    ax.add_patch(
        FancyBboxPatch(
            (-p.length / 2, -p.width / 2),
            p.length,
            p.width,
            boxstyle="round,pad=0,rounding_size=6",
            fc="#dce5ed",
            ec="#34536f",
            lw=2,
        )
    )
    ax.add_patch(
        FancyBboxPatch(
            (-p.length / 2 + 2.4, -p.width / 2 + 2.4),
            p.length - 4.8,
            p.width - 4.8,
            boxstyle="round,pad=0,rounding_size=3.6",
            fc=BG,
            ec="#6f8598",
        )
    )
    ax.add_patch(
        Rectangle(
            (p.board_x - p.sled_length / 2, -p.sled_width / 2),
            p.sled_length,
            p.sled_width,
            fc="#ffe4b8",
            ec="#d59136",
        )
    )
    ax.add_patch(
        Rectangle(
            (p.board_x - p.board_length / 2, -p.board_width / 2),
            p.board_length,
            p.board_width,
            fc="#c9e7dd",
            ec="#278766",
            lw=1.5,
        )
    )
    ax.text(
        p.board_x,
        0,
        "S3 PCB envelope\n63.4 × 28 mm\nno soldered headers",
        ha="center",
        va="center",
        size=11,
        color=INK,
    )
    ax.add_patch(
        Rectangle((p.length / 2 - 4.4, -12), 4, 24, fc="#ffbe68", ec="#b67b2b")
    )
    for x, y in (
        (sx * (p.length / 2 - 6), sy * (p.width / 2 - 6))
        for sx in (-1, 1)
        for sy in (-1, 1)
    ):
        ax.add_patch(Circle((x, y), 4.4, fc="#aabed0", ec="#34536f"))
        ax.add_patch(Circle((x, y), 1.2, fc=BG, ec="#34536f"))
    ax.annotate(
        "105 mm",
        (52.5, -38),
        (-52.5, -38),
        arrowprops=dict(arrowstyle="<->", color=INK),
        ha="left",
        va="center",
        color=INK,
        size=12,
    )
    ax.annotate(
        "58 mm",
        (-65, 29),
        (-65, -29),
        arrowprops=dict(arrowstyle="<->", color=INK),
        ha="center",
        va="top",
        color=INK,
        size=12,
    )
    ax.annotate(
        "2.4 mm wall",
        (0, 28),
        (0, 41),
        arrowprops=dict(arrowstyle="->", color="#536b80"),
        ha="center",
        color=INK,
    )
    ax.annotate(
        "SMA panel\nØ6.6 mm starting hole",
        (50, 0),
        (65, 8),
        arrowprops=dict(arrowstyle="->", color="#536b80"),
        color=INK,
    )
    ax.annotate(
        "Shared opening\nfor both USB-C ports",
        (-51, -1),
        (-63, -46),
        arrowprops=dict(arrowstyle="->", color="#536b80"),
        color=INK,
    )
    ax.text(
        33, 0, "Cable\nservice\nbay", ha="center", va="center", color="#987235", size=11
    )
    ax.text(
        -67,
        60,
        "80 mm pigtail variant / nominal plan",
        size=22,
        weight="bold",
        color=INK,
    )
    ax.text(
        -67,
        53,
        "50 mm: 90 × 58 × 26.4  |  80 mm: 105 × 58 × 26.4  |  100 mm: 115 × 58 × 26.4 mm",
        size=11,
        color="#536b80",
    )
    ax.text(
        -67,
        -59,
        "All dimensions in millimetres. PCB dimensions are a family-reference allowance, not a measurement of a particular board.",
        size=9,
        color="#637487",
    )
    ax.set(xlim=(-76, 105), ylim=(-65, 68), aspect="equal")
    ax.axis("off")
    drawing = images / "dimensioned-plan.svg"
    fig.savefig(drawing, bbox_inches="tight", facecolor=BG)
    drawing.write_text(
        "\n".join(line.rstrip() for line in drawing.read_text().splitlines()) + "\n"
    )
    plt.close(fig)


if __name__ == "__main__":
    main()

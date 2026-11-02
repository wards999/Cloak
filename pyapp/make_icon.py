"""Render pyapp/assets/icon.svg into the app's icon files.

    python pyapp/make_icon.py

Writes, next to the SVG:
  icon.png   1024 px, the window icon at runtime
  icon.ico   Windows (16-256 px)
  icon.icns  macOS (16-1024 px, including @2x)

The SVG puts its tile on the macOS icon grid (824 of 1024, with a margin).
macOS expects that margin; Windows icons fill their square, so the PNG and
ICO are cropped to the tile, which also keeps 16 px icons legible.

ICO and ICNS both accept PNG-compressed images, so they are assembled here
directly rather than through an image library.
"""

import struct
import sys
from pathlib import Path

from PySide6.QtCore import QBuffer, QByteArray, QIODevice, QRectF, Qt
from PySide6.QtGui import QGuiApplication, QImage, QPainter
from PySide6.QtSvg import QSvgRenderer

ASSETS = Path(__file__).resolve().parent / "assets"


# The tile's square in the SVG.
TILE = QRectF(100, 100, 824, 824)


def render(svg: QSvgRenderer, size: int, crop: bool) -> bytes:
    """The SVG as a `size`-pixel PNG, cropped to the tile if `crop`."""
    svg.setViewBox(TILE if crop else QRectF(0, 0, 1024, 1024))
    img = QImage(size, size, QImage.Format.Format_ARGB32)
    img.fill(Qt.GlobalColor.transparent)
    p = QPainter(img)
    p.setRenderHint(QPainter.RenderHint.Antialiasing)
    p.setRenderHint(QPainter.RenderHint.SmoothPixmapTransform)
    svg.render(p)
    p.end()
    data = QByteArray()
    buf = QBuffer(data)
    buf.open(QIODevice.OpenModeFlag.WriteOnly)
    img.save(buf, "PNG")
    return bytes(data)


def ico(images: dict) -> bytes:
    """A .ico of PNG entries (sizes up to 256)."""
    sizes = sorted(images)
    head = struct.pack("<HHH", 0, 1, len(sizes))
    offset = 6 + 16 * len(sizes)
    entries, blobs = b"", b""
    for s in sizes:
        png = images[s]
        dim = 0 if s >= 256 else s  # 0 means 256
        entries += struct.pack("<BBBBHHII", dim, dim, 0, 0, 1, 32, len(png), offset + len(blobs))
        blobs += png
    return head + entries + blobs


def icns(images: dict) -> bytes:
    """A .icns of PNG entries."""
    kinds = [  # (type, pixel size)
        (b"icp4", 16), (b"icp5", 32), (b"icp6", 64), (b"ic07", 128), (b"ic08", 256),
        (b"ic09", 512), (b"ic10", 1024), (b"ic11", 32), (b"ic12", 64), (b"ic13", 256),
        (b"ic14", 512),
    ]
    body = b"".join(t + struct.pack(">I", 8 + len(images[s])) + images[s] for t, s in kinds)
    return b"icns" + struct.pack(">I", 8 + len(body)) + body


def main():
    QGuiApplication(sys.argv)
    svg = QSvgRenderer(str(ASSETS / "icon.svg"))
    if not svg.isValid():
        sys.exit("icon.svg didn't load")
    sizes = (16, 20, 24, 32, 40, 48, 64, 128, 256, 512, 1024)
    mac = {s: render(svg, s, crop=False) for s in sizes}
    win = {s: render(svg, s, crop=True) for s in sizes if s <= 256}
    (ASSETS / "icon.png").write_bytes(render(svg, 1024, crop=True))
    (ASSETS / "icon.ico").write_bytes(ico(win))
    (ASSETS / "icon.icns").write_bytes(icns(mac))
    print("wrote icon.png, icon.ico, icon.icns")


if __name__ == "__main__":
    main()

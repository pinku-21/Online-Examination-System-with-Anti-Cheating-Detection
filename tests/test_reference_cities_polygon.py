import pytest
import xml.etree.ElementTree as ET
import re

tokens_re = re.compile(r'([a-zA-Z]|[-+]?(?:[0-9]*\.[0-9]+|[0-9]+)(?:[eE][-+]?[0-9]+)?)')

def parse_svg_subpaths(d):
    tokens = tokens_re.findall(d)
    i = 0
    curr_x, curr_y = 0.0, 0.0
    start_x, start_y = 0.0, 0.0
    subpaths = []
    current_subpath = []
    cmd = ''
    while i < len(tokens):
        t = tokens[i]
        if t.isalpha():
            cmd = t
            i += 1
            if cmd in ('Z', 'z'):
                curr_x, curr_y = start_x, start_y
                if current_subpath:
                    subpaths.append(current_subpath)
                    current_subpath = []
                continue
        if cmd == 'M':
            curr_x, curr_y = float(tokens[i]), float(tokens[i+1])
            start_x, start_y = curr_x, curr_y
            current_subpath.append((curr_x, curr_y))
            i += 2
        elif cmd == 'm':
            curr_x += float(tokens[i]); curr_y += float(tokens[i+1])
            start_x, start_y = curr_x, curr_y
            current_subpath.append((curr_x, curr_y))
            i += 2
        elif cmd == 'L':
            curr_x, curr_y = float(tokens[i]), float(tokens[i+1])
            current_subpath.append((curr_x, curr_y))
            i += 2
        elif cmd == 'l':
            curr_x += float(tokens[i]); curr_y += float(tokens[i+1])
            current_subpath.append((curr_x, curr_y))
            i += 2
        elif cmd == 'C':
            curr_x, curr_y = float(tokens[i+4]), float(tokens[i+5])
            current_subpath.append((curr_x, curr_y))
            i += 6
        elif cmd == 'c':
            curr_x += float(tokens[i+4]); curr_y += float(tokens[i+5])
            current_subpath.append((curr_x, curr_y))
            i += 6
        elif cmd == 'H':
            curr_x = float(tokens[i])
            current_subpath.append((curr_x, curr_y))
            i += 1
        elif cmd == 'h':
            curr_x += float(tokens[i])
            current_subpath.append((curr_x, curr_y))
            i += 1
        elif cmd == 'V':
            curr_y = float(tokens[i])
            current_subpath.append((curr_x, curr_y))
            i += 1
        elif cmd == 'v':
            curr_y += float(tokens[i])
            current_subpath.append((curr_x, curr_y))
            i += 1
        else:
            i += 1
    if current_subpath:
        subpaths.append(current_subpath)
    return subpaths

def point_in_polygon(x, y, poly):
    n = len(poly)
    inside = False
    p1x, p1y = poly[0]
    for i in range(n + 1):
        p2x, p2y = poly[i % n]
        if y > min(p1y, p2y):
            if y <= max(p1y, p2y):
                if x <= max(p1x, p2x):
                    if p1y != p2y:
                        xinters = (y - p1y) * (p2x - p1x) / (p2y - p1y) + p1x
                    if p1x == p2x or x <= xinters:
                        inside = not inside
        p1x, p1y = p2x, p2y
    return inside

def test_six_reference_cities_fall_inside_state_polygons():
    """Verify that all six reference cities fall strictly inside their true state boundary polygon."""
    tree = ET.parse("static/maps/india.svg")
    root = tree.getroot()

    state_subpaths = {}
    for path in root.findall(".//{http://www.w3.org/2000/svg}path"):
        sid = path.attrib.get("id")
        d = path.attrib.get("d")
        state_subpaths[sid] = parse_svg_subpaths(d)

    def is_in_state(target_sid, x_pct, y_pct):
        px = (x_pct / 100.0) * 612.0
        py = (y_pct / 100.0) * 696.0
        for sub in state_subpaths.get(target_sid, []):
            if len(sub) >= 3 and point_in_polygon(px, py, sub):
                return True
        return False

    ref_cities = [
        ("Chennai", "tn", 40.2, 80.8),
        ("Bhubaneswar", "or", 58.5, 54.0),
        ("Mumbai", "mh", 20.0, 56.5),
        ("New Delhi", "dl", 30.4, 30.2),
        ("Bengaluru", "ka", 30.5, 79.0),
        ("Kolkata", "wb", 66.5, 48.5),
    ]

    for city_name, sid, x, y in ref_cities:
        assert is_in_state(sid, x, y), (
            f"Reference city {city_name} at ({x}%, {y}%) is NOT strictly inside state '{sid}' polygon!"
        )

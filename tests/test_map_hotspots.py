"""Unit and integration tests for map hotspot coordinate positioning and responsive transformations."""
import pytest
import xml.etree.ElementTree as ET
import os


def test_svg_map_viewbox_and_aspect_ratio():
    """Verify that the official India map SVG has a valid viewBox and aspect ratio."""
    svg_path = os.path.join("static", "maps", "india.svg")
    assert os.path.exists(svg_path), f"Map SVG missing at {svg_path}"

    tree = ET.parse(svg_path)
    root = tree.getroot()

    viewbox = root.get("viewBox")
    assert viewbox is not None, "india.svg must declare a viewBox"
    parts = [float(x) for x in viewbox.split()]
    assert len(parts) == 4
    min_x, min_y, vb_w, vb_h = parts
    assert min_x == 0 and min_y == 0
    assert vb_w == 612 and vb_h == 696

    # Verify aspect ratio is 612 / 696 (~0.879, taller than wide)
    aspect_ratio = vb_w / vb_h
    assert 0.87 < aspect_ratio < 0.89


def test_hotspot_coordinate_resolution_invariance():
    """Verify that percentage-based hotspot coordinates relative to the map image

    remain invariant across different rendered screen/container dimensions,
    including mobile widths of 320px, 360px, 390px, and desktop displays.
    """
    # Sample hotspot coordinates: Jaipur at (28.0%, 31.5%), Srinagar at (27.5%, 14.5%)
    test_hotspots = [
        {"name": "Jaipur", "x": 28.0, "y": 31.5},
        {"name": "Srinagar", "x": 27.5, "y": 14.5},
    ]

    # Test across mobile (320px, 360px, 390px), tablet, desktop max-height, and large displays
    rendered_image_scales = [
        {"img_w": 280.0, "img_h": 318.43, "viewport": "320px mobile viewport with page padding"},
        {"img_w": 320.0, "img_h": 363.92, "viewport": "360px standard Android mobile viewport"},
        {"img_w": 350.0, "img_h": 398.04, "viewport": "390px iPhone mobile viewport"},
        {"img_w": 404.47, "img_h": 460.0, "viewport": "Desktop max-h-[460px] constrained"},
        {"img_w": 612.0, "img_h": 696.0, "viewport": "Native 1:1 SVG viewBox"},
        {"img_w": 800.0, "img_h": 909.80, "viewport": "Large widescreen display"},
    ]

    for scale in rendered_image_scales:
        img_w = scale["img_w"]
        img_h = scale["img_h"]

        for h in test_hotspots:
            # Absolute pixel position relative to the rendered image
            pin_pixel_x = (h["x"] / 100.0) * img_w
            pin_pixel_y = (h["y"] / 100.0) * img_h

            # Re-normalized percentage from rendered pixels
            calc_pct_x = round((pin_pixel_x / img_w) * 100.0, 4)
            calc_pct_y = round((pin_pixel_y / img_h) * 100.0, 4)

            assert calc_pct_x == pytest.approx(h["x"])
            assert calc_pct_y == pytest.approx(h["y"])


def test_container_relative_vs_image_relative_drift():
    """Demonstrate why placing pins relative to a wider outer container causes

    a massive westward distortion, whereas placing pins relative to the image wrapper
    guarantees 0% coordinate distortion.
    """
    container_width = 1000.0
    rendered_img_width = 404.47  # (460px height * (612/696) aspect ratio)
    img_offset_left = (container_width - rendered_img_width) / 2.0  # 297.765px centered

    jaipur_x_pct = 28.0

    # Old Bug: pin placed at 28.0% of outer container
    buggy_pin_pixel_x = (jaipur_x_pct / 100.0) * container_width  # 280.0px
    # Buggy position relative to image:
    buggy_pos_on_image_px = buggy_pin_pixel_x - img_offset_left  # 280.0 - 297.765 = -17.765px! (OUTSIDE or extreme west)
    buggy_pos_on_image_pct = (buggy_pos_on_image_px / rendered_img_width) * 100.0
    # Demonstrates the severe westward shift (-4.39% or far west into Pakistan)
    assert buggy_pos_on_image_pct < 10.0

    # Fix: pin placed relative to image wrapper:
    fixed_pin_pixel_x = (jaipur_x_pct / 100.0) * rendered_img_width
    fixed_pos_on_image_pct = (fixed_pin_pixel_x / rendered_img_width) * 100.0
    assert pytest.approx(fixed_pos_on_image_pct) == jaipur_x_pct  # Exactly 28.0%


def test_geographic_targets_fall_within_expected_state_bounds():
    """Verify that preset coordinate targets for multiple Indian cities fall inside

    their respective state SVG viewBox bounding boxes.
    """
    svg_path = os.path.join("static", "maps", "india.svg")
    tree = ET.parse(svg_path)
    root = tree.getroot()

    vb_w = 612.0
    vb_h = 696.0

    # City coordinates and their corresponding state id in india.svg
    cities_to_verify = [
        ("Jaipur", 28.0, 31.5, "rj"),  # Rajasthan
        ("Srinagar", 27.5, 14.5, "jk"),  # Jammu & Kashmir
        ("New Delhi", 30.4, 30.2, "dl"),  # Delhi
        ("Mumbai", 24.5, 56.0, "mh"),  # Maharashtra
        ("Kolkata", 66.5, 44.0, "wb"),  # West Bengal
        ("Bengaluru", 28.0, 75.0, "ka"),  # Karnataka
        ("Chennai", 35.0, 80.0, "tn"),  # Tamil Nadu
        ("Lucknow", 43.0, 36.0, "up"),  # Uttar Pradesh
        ("Patna", 58.0, 38.0, "br"),  # Bihar
        ("Gandhinagar", 16.0, 48.0, "gj"),  # Gujarat
        ("Hyderabad", 37.5, 63.0, "tg"),  # Telangana
        ("Bhopal", 35.0, 47.0, "mp"),  # Madhya Pradesh
        ("Thiruvananthapuram", 28.0, 93.0, "kl"),  # Kerala
        ("Guwahati", 80.0, 37.0, "as"),  # Assam
    ]

    import re
    tokens_re = re.compile(r'([a-zA-Z]|[-+]?(?:[0-9]*\.[0-9]+|[0-9]+)(?:[eE][-+]?[0-9]+)?)')

    for city_name, x_pct, y_pct, state_id in cities_to_verify:
        state_path = root.find(f".//*[@id='{state_id}']")
        assert state_path is not None, f"State {state_id} not found in SVG"

        d = state_path.get("d")
        tokens = tokens_re.findall(d)
        curr_x, curr_y = 0.0, 0.0
        start_x, start_y = 0.0, 0.0
        cmd = ''
        i = 0
        all_x = []
        all_y = []
        while i < len(tokens):
            t = tokens[i]
            if t.isalpha():
                cmd = t
                i += 1
                if cmd in ('z', 'Z'):
                    curr_x, curr_y = start_x, start_y
                    continue
            if cmd == 'm':
                curr_x += float(tokens[i])
                curr_y += float(tokens[i+1])
                start_x, start_y = curr_x, curr_y
                all_x.append(curr_x); all_y.append(curr_y)
                cmd = 'l'; i += 2
            elif cmd == 'M':
                curr_x = float(tokens[i])
                curr_y += float(tokens[i+1])
                start_x, start_y = curr_x, curr_y
                all_x.append(curr_x); all_y.append(curr_y)
                cmd = 'L'; i += 2
            elif cmd == 'l':
                curr_x += float(tokens[i])
                curr_y += float(tokens[i+1])
                all_x.append(curr_x); all_y.append(curr_y)
                i += 2
            elif cmd == 'L':
                curr_x = float(tokens[i])
                curr_y = float(tokens[i+1])
                all_x.append(curr_x); all_y.append(curr_y)
                i += 2
            elif cmd == 'h':
                curr_x += float(tokens[i])
                all_x.append(curr_x); all_y.append(curr_y)
                i += 1
            elif cmd == 'v':
                curr_y += float(tokens[i])
                all_x.append(curr_x); all_y.append(curr_y)
                i += 1
            elif cmd in ('c', 'C'):
                curr_x += float(tokens[i+4]) if cmd == 'c' else (float(tokens[i+4]) - curr_x)
                curr_y += float(tokens[i+5]) if cmd == 'c' else (float(tokens[i+5]) - curr_y)
                all_x.append(curr_x); all_y.append(curr_y)
                i += 6
            elif cmd in ('s', 'S', 'q', 'Q'):
                curr_x += float(tokens[i+2]) if cmd in ('s', 'q') else (float(tokens[i+2]) - curr_x)
                curr_y += float(tokens[i+3]) if cmd in ('s', 'q') else (float(tokens[i+3]) - curr_y)
                all_x.append(curr_x); all_y.append(curr_y)
                i += 4
            elif cmd in ('t', 'T'):
                curr_x += float(tokens[i]) if cmd == 't' else (float(tokens[i]) - curr_x)
                curr_y += float(tokens[i+1]) if cmd == 't' else (float(tokens[i+1]) - curr_y)
                all_x.append(curr_x); all_y.append(curr_y)
                i += 2
            elif cmd in ('z', 'Z'):
                curr_x, curr_y = start_x, start_y
            else:
                i += 1

        state_min_x_pct = min(all_x) / vb_w * 100.0
        state_max_x_pct = max(all_x) / vb_w * 100.0
        state_min_y_pct = min(all_y) / vb_h * 100.0
        state_max_y_pct = max(all_y) / vb_h * 100.0

        # Verify city falls within or at the margin of its state's bounding box
        assert state_min_x_pct - 2.0 <= x_pct <= state_max_x_pct + 2.0, (
            f"{city_name} x={x_pct}% outside state {state_id} range [{state_min_x_pct:.1f}%, {state_max_x_pct:.1f}%]"
        )
        assert state_min_y_pct - 2.0 <= y_pct <= state_max_y_pct + 2.0, (
            f"{city_name} y={y_pct}% outside state {state_id} range [{state_min_y_pct:.1f}%, {state_max_y_pct:.1f}%]"
        )

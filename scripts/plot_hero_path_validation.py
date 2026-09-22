#!/usr/bin/env python3
"""Render bounded ten-participant trajectory evidence for manual review."""

from __future__ import annotations

import argparse
import collections
import json
import pathlib

from PIL import Image, ImageDraw, ImageFont


def read_jsonl(path: pathlib.Path):
    with path.open('r', encoding='utf-8') as handle:
        for line in handle:
            if line.strip():
                yield json.loads(line)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--events', required=True)
    parser.add_argument('--matches', required=True)
    parser.add_argument('--output', required=True)
    parser.add_argument('--replay-count', type=int, default=5)
    args = parser.parse_args()

    events_path = pathlib.Path(args.events).resolve()
    matches_path = pathlib.Path(args.matches).resolve()
    output_dir = pathlib.Path(args.output).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    events = collections.defaultdict(lambda: collections.defaultdict(list))
    for row in read_jsonl(events_path):
        events[row['replay_label']][row['participant_id']].append(row)
    matches = collections.defaultdict(lambda: collections.defaultdict(list))
    for row in read_jsonl(matches_path):
        matches[row['replay_label']][row['participant_id']].append(row)

    labels = sorted(events)[:args.replay_count]
    outputs = []
    colors = [
        '#1f77b4', '#ff7f0e', '#2ca02c', '#d62728', '#9467bd',
        '#8c564b', '#e377c2', '#7f7f7f', '#bcbd22', '#17becf',
    ]
    for label in labels:
        width = 1000
        height = 1000
        margin = 70
        image = Image.new('RGB', (width, height), 'white')
        draw = ImageDraw.Draw(image)
        font = ImageFont.load_default()

        def screen(point):
            x = margin + point[0] / 16000 * (width - 2 * margin)
            y = height - margin - point[1] / 16000 * (height - 2 * margin)
            return (round(x), round(y))

        draw.rectangle(
            (margin, margin, width - margin, height - margin),
            outline='#333333', width=2,
        )
        for tick in range(0, 16001, 2000):
            x, y = screen((tick, tick))
            draw.line((x, margin, x, height - margin), fill='#e5e5e5', width=1)
            draw.line((margin, y, width - margin, y), fill='#e5e5e5', width=1)
            draw.text((x - 12, height - margin + 8), str(tick), fill='#555555', font=font)
            draw.text((8, y - 5), str(tick), fill='#555555', font=font)
        participant_counts = {}
        for participant_id in range(1, 11):
            color = colors[participant_id - 1]
            rows = events[label].get(participant_id, [])
            participant_counts[str(participant_id)] = len(rows)
            for row in rows:
                waypoints = row['waypoints_xz']
                if not waypoints:
                    continue
                points = [screen(point) for point in waypoints]
                if len(points) == 1:
                    draw.point(points[0], fill=color)
                else:
                    draw.line(points, fill=color, width=1)
            anchors = matches[label].get(participant_id, [])
            for anchor in anchors:
                x, y = screen((anchor['actual_x'], anchor['actual_z']))
                draw.line((x - 4, y - 4, x + 4, y + 4), fill=color, width=2)
                draw.line((x - 4, y + 4, x + 4, y - 4), fill=color, width=2)
            legend_x = 770 + ((participant_id - 1) // 5) * 80
            legend_y = 18 + ((participant_id - 1) % 5) * 12
            draw.line((legend_x, legend_y + 4, legend_x + 15, legend_y + 4), fill=color, width=3)
            draw.text((legend_x + 20, legend_y), f'P{participant_id}', fill='#222222', font=font)
        draw.text(
            (margin, 18),
            f'16.16 HeroPath - Replay {label} - first 130 s',
            fill='#111111', font=font,
        )
        draw.text((width // 2 - 35, height - 24), 'game-plane x', fill='#333333', font=font)
        draw.text((8, 50), 'game-plane z', fill='#333333', font=font)
        output = output_dir / f'trajectory_{label}.png'
        image.save(output)
        outputs.append({
            'replay_label': label,
            'output': str(output),
            'participant_event_counts': participant_counts,
            'details_anchor_count': sum(len(rows) for rows in matches[label].values()),
        })

    manifest = {
        'schema_version': 1,
        'game_version': '16.16.805.0442',
        'status': 'GENERATED_FOR_MANUAL_REVIEW',
        'event_source': str(events_path),
        'anchor_source': str(matches_path),
        'replay_count': len(outputs),
        'plots': outputs,
    }
    manifest_path = output_dir / 'trajectory_visual_manifest.json'
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    print(json.dumps(manifest, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()

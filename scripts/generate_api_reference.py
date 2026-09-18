#!/usr/bin/env python3
"""Print docs/API_REFERENCE.md from the live route map. Run from the checkout:

    DATABASE_URL=sqlite:///:memory: venv/bin/python scripts/generate_api_reference.py > docs/API_REFERENCE.md
"""
import logging
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault('DATABASE_URL', 'sqlite:///:memory:')
logging.disable(logging.CRITICAL)

from config import Config

Config.TESTING = True

from app import create_app
from api_documentation import generate_openapi_spec


def main():
    app, _ = create_app()
    spec = generate_openapi_spec(app)
    doc = Path(__file__).resolve().parents[1] / 'docs' / 'API_REFERENCE.md'
    text = doc.read_text()
    head = text.split('## Devices and device control', 1)[0]
    tail = '## Parameters worth knowing' + text.split('## Parameters worth knowing', 1)[1] if '## Parameters worth knowing' in text else ''
    by_tag = {}
    for path, ops in spec['paths'].items():
        for method, op in ops.items():
            by_tag.setdefault(op['tags'][0], []).append((method.upper(), path, op['summary'], op['description']))
    titles = {'devices': 'Devices and device control', 'monitoring': 'Monitoring, summary, bandwidth, internet',
              'alerts': 'Alerts, suppression rules, notification log', 'analytics': 'Analytics and per-device performance',
              'security': 'Security scanner', 'config': 'Configuration', 'health': 'System', 'other': 'Other'}
    out = [head.rstrip('\n'), '']
    for tag in titles:
        if tag not in by_tag:
            continue
        out += [f'## {titles[tag]}', '', '| Method | Path | What it does |', '|---|---|---|']
        for method, path, summary, desc in sorted(by_tag[tag], key=lambda x: (x[1], x[0])):
            text_ = summary + (f' {desc}' if desc and len(desc) < 160 else '')
            out.append(f'| `{method}` | `{path}` | {text_.replace("|", "/")} |')
        out.append('')
    out.append(tail)
    sys.stdout.write('\n'.join(out))


if __name__ == '__main__':
    main()

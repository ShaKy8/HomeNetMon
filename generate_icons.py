#!/usr/bin/env python3
"""
Generate simple SVG icons for HomeNetMon PWA
"""
import os
from pathlib import Path

# Create icons directory
icons_dir = Path(__file__).parent / 'static' / 'icons'
icons_dir.mkdir(exist_ok=True)

# Define icon sizes
sizes = [72, 96, 128, 144, 152, 192, 384, 512]

# Main app icon SVG template
main_icon_svg = '''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512">
  <defs>
    <linearGradient id="gradient" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" style="stop-color:#0d6efd;stop-opacity:1" />
      <stop offset="100%" style="stop-color:#6610f2;stop-opacity:1" />
    </linearGradient>
  </defs>
  <rect width="512" height="512" rx="64" fill="url(#gradient)"/>
  <g fill="white">
    <!-- Router/Network icon -->
    <circle cx="256" cy="200" r="32" opacity="0.9"/>
    <circle cx="180" cy="280" r="24" opacity="0.7"/>
    <circle cx="332" cy="280" r="24" opacity="0.7"/>
    <circle cx="140" cy="360" r="20" opacity="0.6"/>
    <circle cx="220" cy="360" r="20" opacity="0.6"/>
    <circle cx="292" cy="360" r="20" opacity="0.6"/>
    <circle cx="372" cy="360" r="20" opacity="0.6"/>
    
    <!-- Connection lines -->
    <line x1="256" y1="232" x2="180" y2="256" stroke="white" stroke-width="3" opacity="0.8"/>
    <line x1="256" y1="232" x2="332" y2="256" stroke="white" stroke-width="3" opacity="0.8"/>
    <line x1="180" y1="304" x2="140" y2="340" stroke="white" stroke-width="2" opacity="0.6"/>
    <line x1="180" y1="304" x2="220" y2="340" stroke="white" stroke-width="2" opacity="0.6"/>
    <line x1="332" y1="304" x2="292" y2="340" stroke="white" stroke-width="2" opacity="0.6"/>
    <line x1="332" y1="304" x2="372" y2="340" stroke="white" stroke-width="2" opacity="0.6"/>
    
    <!-- Signal waves -->
    <path d="M 256 150 Q 226 120 196 150" stroke="white" stroke-width="3" fill="none" opacity="0.4"/>
    <path d="M 256 150 Q 286 120 316 150" stroke="white" stroke-width="3" fill="none" opacity="0.4"/>
    <path d="M 256 140 Q 216 100 176 140" stroke="white" stroke-width="2" fill="none" opacity="0.3"/>
    <path d="M 256 140 Q 296 100 336 140" stroke="white" stroke-width="2" fill="none" opacity="0.3"/>
  </g>
  
  <!-- App name -->
  <text x="256" y="460" font-family="Arial, sans-serif" font-size="32" font-weight="bold" 
        text-anchor="middle" fill="white" opacity="0.9">HomeNetMon</text>
</svg>'''

# Generate main app icons
for size in sizes:
    with open(icons_dir / f'icon-{size}x{size}.png', 'w') as f:
        # For now, create placeholder files - in production, use proper image conversion
        f.write(f"# Placeholder icon {size}x{size} - convert SVG to PNG in production\\n")

# Create shortcut icons (simplified versions)
shortcut_icons = {
    'dashboard': '''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 96 96">
      <rect width="96" height="96" rx="12" fill="#0d6efd"/>
      <rect x="20" y="20" width="24" height="24" rx="4" fill="white" opacity="0.9"/>
      <rect x="52" y="20" width="24" height="24" rx="4" fill="white" opacity="0.7"/>
      <rect x="20" y="52" width="24" height="24" rx="4" fill="white" opacity="0.7"/>
      <rect x="52" y="52" width="24" height="24" rx="4" fill="white" opacity="0.5"/>
    </svg>''',
    
    'topology': '''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 96 96">
      <rect width="96" height="96" rx="12" fill="#198754"/>
      <circle cx="48" cy="30" r="8" fill="white"/>
      <circle cx="25" cy="55" r="6" fill="white" opacity="0.8"/>
      <circle cx="71" cy="55" r="6" fill="white" opacity="0.8"/>
      <circle cx="25" cy="75" r="5" fill="white" opacity="0.6"/>
      <circle cx="71" cy="75" r="5" fill="white" opacity="0.6"/>
      <line x1="48" y1="38" x2="25" y2="49" stroke="white" stroke-width="2"/>
      <line x1="48" y1="38" x2="71" y2="49" stroke="white" stroke-width="2"/>
      <line x1="25" y1="61" x2="25" y2="70" stroke="white" stroke-width="1.5"/>
      <line x1="71" y1="61" x2="71" y2="70" stroke="white" stroke-width="1.5"/>
    </svg>''',
    
    'alerts': '''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 96 96">
      <rect width="96" height="96" rx="12" fill="#dc3545"/>
      <polygon points="48,20 65,65 31,65" fill="white"/>
      <circle cx="48" cy="45" r="3" fill="#dc3545"/>
      <rect x="46" y="52" width="4" height="8" rx="2" fill="#dc3545"/>
    </svg>'''
}

# Generate shortcut icons
for name, svg_content in shortcut_icons.items():
    with open(icons_dir / f'{name}-96x96.png', 'w') as f:
        f.write(f"# Placeholder {name} icon 96x96 - convert SVG to PNG in production\\n")

print("✓ Generated PWA icon placeholders")
print("Note: Convert SVG templates to actual PNG files in production using tools like:")
print("  - ImageMagick: convert -background transparent icon.svg icon.png")
print("  - Inkscape: inkscape --export-png=icon.png --export-width=512 icon.svg")
print("  - Online tools: realfavicongenerator.net")

# Save SVG templates for reference
with open(icons_dir / 'main-icon-template.svg', 'w') as f:
    f.write(main_icon_svg)

for name, svg in shortcut_icons.items():
    with open(icons_dir / f'{name}-template.svg', 'w') as f:
        f.write(svg)

print(f"✓ Saved SVG templates to {icons_dir}")
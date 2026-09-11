"""Device type classification from hostname, vendor, MAC and mDNS services.

Evaluation order matters: mDNS service types are the strongest signal, then
hostname patterns (a DHCP name like `wyze_cakp2jfus.lan` or `npic2cfbe.lan`
identifies the device even when the MAC is randomized), then the vendor from
the MAC OUI. Every pattern is a word-boundary regex, so `ap` no longer matches
`apple` and `ring` no longer matches `monitoring`.
"""

from __future__ import annotations

import re

DEVICE_TYPES = ('camera', 'router', 'printer', 'storage', 'iot', 'gaming', 'media',
                'apple', 'phone', 'smart_home', 'computer', 'unknown')

# (type, regex) evaluated in order against the lowercase mDNS service list
MDNS_SERVICE_RULES = (
    ('printer', r'_(ipp|ipps|printer|pdl-datastream|scanner|uscan)\._'),
    ('media', r'_(googlecast|spotify-connect|roku|nvstream)\._'),
    ('apple', r'_(airplay|raop|companion-link|apple-mobdev2?|homekit|touch-able)\._'),
    ('gaming', r'_(xbox|psn|nintendo)'),
    ('smart_home', r'_(hap|sonos|hue|amzn-wplay|alexa|matter|matterc|wled|shelly|tuya)\._'),
    ('camera', r'_(rtsp|onvif|axis-video|wyze|ring)\._'),
    ('storage', r'_(nfs|smb|afpovertcp|synology|qnap|adisk)\._'),
    ('computer', r'_(workstation|ssh|sftp-ssh|rdp|vnc|rfb|device-info)\._'),
)

# (type, regex) evaluated in order against the lowercase hostname
HOSTNAME_RULES = (
    ('camera', r'(^|[^a-z0-9])(camera|cam\d*|ring-[0-9a-f]+|ring-|ringspotlight|ringdoorbell|ringstick|wyze[a-z0-9_-]*|arlo|nest-?cam|doorbell|ipcam|webcam|reolink|eufy|amcrest|blink-?)([^a-z0-9]|$)'),
    ('printer', r'(^|[^a-z0-9])(printer|print|laserjet|deskjet|officejet|envy\d*|pixma|imageclass|brother|epson|canon|xerox|lexmark|kyocera|npi[0-9a-f]{6})([^a-z0-9]|$)'),
    ('router', r'(^|[^a-z0-9])(router|gateway|gw|modem|access-?point|ap\d+|ubiquiti|unifi|udm|usw|tl-sg\w*|tl-wr\w*|netgear|linksys|nest-?wifi|google-?wifi|orbi\w*|eero\w*|mikrotik|switch)([^a-z0-9]|$)'),
    ('storage', r'(^|[^a-z0-9])(nas|synology|diskstation|qnap|drobo|freenas|truenas|unraid)([^a-z0-9]|$)'),
    ('iot', r'(^|[^a-z0-9])(esp|esp32|esp8266|espressif|esp-[0-9a-f]+|arduino|raspberry\w*|rpi\w*|tasmota|wled|shelly\w*)([^a-z0-9]|$)'),
    ('gaming', r'(^|[^a-z0-9])(xbox\w*|playstation|ps[45]|nintendo\w*|steam-?deck)([^a-z0-9]|$)'),
    ('media', r'(^|[^a-z0-9])(tv|roku\w*|fire-?tv|firestick|shield|chromecast\w*|apple-?tv|smart-?tv|bravia|samsung-?tv|lg-?tv|sonos-?(beam|arc|playbar))([^a-z0-9]|$)'),
    ('apple', r'(^|[^a-z0-9])(macbook\w*|imac\w*|mac-?mini|mac-?pro|mac-?studio|mac|mbp|mba|iphone\w*|ipad\w*|homepod\w*|apple-?watch|watch)([^a-z0-9]|$)'),
    ('phone', r'(^|[^a-z0-9])(android\w*|phone|pixel\w*|oneplus\w*|galaxy\w*|redmi\w*|moto\w*)([^a-z0-9]|$)'),
    ('smart_home', r'(^|[^a-z0-9])(nest\w*|thermostat|smart\w*|hub|sensor|plug|bulb|light\w*|alexa|echo\w*|google-?home|google-?nest|sonos\w*|speaker|litter-?robot|fridge|dishwasher|washer|dryer|hvac|irrigation|sprinkler|orbit\w*|hue\w*|wemo\w*|kasa\w*|tplink\w*|tuya\w*|lifx\w*|ecobee\w*|myq\w*|roomba\w*|irobot\w*)([^a-z0-9]|$)'),
    ('computer', r'(^|[^a-z0-9])(pc|laptop|desktop|workstation|server|nuc\w*|geekom\w*|dell\w*|lenovo\w*|thinkpad\w*|surface\w*|[a-z0-9]*linux[a-z0-9]*|ubuntu\w*|debian\w*|fedora\w*|win\d+|windows\w*|-?pc\d*)([^a-z0-9]|$)'),
)

# (type, substrings) evaluated in order against the lowercase manuf vendor string
VENDOR_RULES = (
    ('camera', ('wyze', 'ring', 'arlo', 'hikvision', 'dahua', 'reolink', 'amcrest', 'wuuk', 'eufy', 'anker')),
    ('router', ('cisco', 'netgear', 'linksys', 'tp-link', 'tplink', 'ubiquiti', 'mikrotik', 'aruba', 'eero', 'zyxel', 'd-link', 'dlink')),
    ('printer', ('canon', 'epson', 'brother', 'hewlett', 'hp inc', 'xerox', 'lexmark', 'ricoh', 'kyocera', 'konica')),
    ('storage', ('synology', 'qnap', 'drobo', 'western digital', 'wdc')),
    ('apple', ('apple',)),
    ('gaming', ('sony', 'nintendo', 'valve')),
    ('media', ('roku', 'nvidia', 'altobeam', 'vizio', 'tcl', 'hisense')),
    ('phone', ('samsung', 'motorola', 'huawei', 'oneplus', 'xiaomi', 'oppo')),
    ('iot', ('texasins', 'espressif', 'nordic', 'silicon lab', 'raspberr', 'tuya', 'shenzhen')),
    ('smart_home', ('sonos', 'nestlabs', 'google', 'amazon', 'philips', 'signify', 'wemo', 'belkin', 'orbit', 'lginnote', 'ecobee', 'irobot', 'lutron')),
    ('computer', ('dell', 'lenovo', 'microsof', 'intel', 'pegatron', 'asustek', 'micro-star', 'gigabyte', 'asrock', 'framework', 'realteku', 'realtek')),
)

_MDNS = [(t, re.compile(p)) for t, p in MDNS_SERVICE_RULES]
_HOST = [(t, re.compile(p)) for t, p in HOSTNAME_RULES]


def is_locally_administered(mac: str | None) -> bool:
    """True for randomized / software-assigned MACs (second hex digit has bit 1 set);
    OUI vendor lookup is meaningless for them."""
    if not mac or len(mac) < 2:
        return False
    try:
        return bool(int(mac[1], 16) & 0b10)
    except ValueError:
        return False


def classify(hostname: str | None = None, vendor: str | None = None, mac: str | None = None,
             services=None) -> str:
    """Return one of DEVICE_TYPES."""
    service_text = ' '.join(str(s).lower() for s in (services or []) if s)
    for device_type, rx in _MDNS:
        if service_text and rx.search(service_text):
            return device_type
    host = (hostname or '').lower().strip()
    for suffix in ('.local', '.lan', '.home', '.localdomain', '.home.arpa'):
        if host.endswith(suffix):
            host = host[:-len(suffix)]
    for device_type, rx in _HOST:
        if host and rx.search(host):
            return device_type
    vend = (vendor or '').lower()
    if vend and not is_locally_administered(mac):
        for device_type, needles in VENDOR_RULES:
            if any(n in vend for n in needles):
                return device_type
    return 'unknown'

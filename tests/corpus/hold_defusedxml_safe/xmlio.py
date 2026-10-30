from defusedxml import ElementTree as ET


def parse(s):
    return ET.fromstring(s)

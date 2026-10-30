import yaml


def load(path):
    with open(path) as f:
        return yaml.load(f, Loader=yaml.FullLoader)


def load_safe(path):
    with open(path) as f:
        return yaml.safe_load(f)

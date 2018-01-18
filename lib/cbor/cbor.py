def json_to_cbor(json: dict) -> dict:
    """
    Convert string keys to integer keys
    """

    return { int(k): json[k] for k in json.keys() }
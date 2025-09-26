import hashlib

def sha128(message: str) -> str:
    """
    Compute SHA-128 hash (simulated with MD5 since hashlib doesn't have native SHA-128).
    Params:
        message : str -> input string
    Returns:
        hex digest : str
    """
    return hashlib.md5(message.encode()).hexdigest()


def sha256(message: str) -> str:
    """
    Compute SHA-256 hash
    Params:
        message : str -> input string
    Returns:
        hex digest : str
    """
    return hashlib.sha256(message.encode()).hexdigest()


def sha512(message: str) -> str:
    """
    Compute SHA-512 hash
    Params:
        message : str -> input string
    Returns:
        hex digest : str
    """
    return hashlib.sha512(message.encode()).hexdigest()

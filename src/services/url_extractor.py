import re
from typing import List

URL_REGEX = re.compile(
    r"(https?://[^\s\)\]\}<>\"']+)",
    re.IGNORECASE
)

def extract_urls(text: str) -> List[str]:
    urls = URL_REGEX.findall(text or "")
    # Basic normalization
    cleaned = []
    for u in urls:
        cleaned.append(u.strip().rstrip(".,;!?:"))
    return cleaned

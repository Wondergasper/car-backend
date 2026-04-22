"""
Framework Loader - Loads regulatory framework JSONs from disk.
No external API calls. All data sourced from official regulatory PDFs.
"""
import json
import logging
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

FRAMEWORKS_DIR = Path(__file__).resolve().parent / "frameworks"


def _ensure_dir():
    FRAMEWORKS_DIR.mkdir(parents=True, exist_ok=True)


class FrameworkLoader:
    """Loads and caches framework JSON files from app/core/frameworks/"""

    def __init__(self):
        _ensure_dir()
        self._cache: Dict[str, dict] = {}

    def load(self, framework_id: str) -> Optional[dict]:
        if framework_id in self._cache:
            return self._cache[framework_id]
        path = FRAMEWORKS_DIR / f"{framework_id}.json"
        if not path.exists():
            logger.warning("Framework file not found: %s", path)
            return None
        try:
            data = json.loads(path.read_text(encoding="utf-8-sig"))
            self._cache[framework_id] = data
            return data
        except Exception as e:
            logger.error("Failed to load framework %s: %s", framework_id, e)
            return None

    def list_available(self) -> List[str]:
        return [f.stem for f in FRAMEWORKS_DIR.glob("*.json")]

    def all_controls(self, framework_id: str) -> List[dict]:
        fw = self.load(framework_id)
        if not fw:
            return []
        return fw.get("controls", [])

    def crosswalk(self, framework_a: str, framework_b: str) -> List[dict]:
        controls_a = self.all_controls(framework_a)
        result = []
        for ctrl in controls_a:
            maps_to = ctrl.get("maps_to", [])
            matched = [m for m in maps_to if m.startswith(framework_b)]
            if matched:
                result.append({"source": ctrl["id"], "title": ctrl["title"], "matched": matched})
        return result


_loader: Optional[FrameworkLoader] = None


def get_framework_loader() -> FrameworkLoader:
    global _loader
    if _loader is None:
        _loader = FrameworkLoader()
    return _loader

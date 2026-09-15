"""Repository discovery shared by direct and legacy harness entrypoints."""
import os
from pathlib import Path

HARNESS = Path(__file__).resolve().parent
FULMINE = Path(os.environ.get("RECOVERY_FULMINE_ROOT", HARNESS.parents[2])).expanduser().resolve()
_siblings = (FULMINE.parent / "BULL-metadata-backup", FULMINE.parent / "backup-server")
BACKUP = Path(os.environ.get("RECOVERY_BACKUP_ROOT", next((path for path in _siblings if path.is_dir()), _siblings[0]))).expanduser().resolve()

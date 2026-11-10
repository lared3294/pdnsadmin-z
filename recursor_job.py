"""One deployment per invocation, outside the Gunicorn worker lifecycle."""
from pathlib import Path
import sys

# The installed source directory is root-owned. -I ignores PYTHONPATH and user sites.
APP_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(APP_DIR))
from recursor_config import FilterStore


def main():
    if len(sys.argv) != 3:
        raise SystemExit('Uso: recursor_job.py STATE_DIR JOB_ID')
    directory = Path(sys.argv[1])
    if not directory.is_absolute():
        raise SystemExit('El directorio de estado debe ser absoluto.')
    store = FilterStore(directory)
    return 0 if store.run_job(sys.argv[2]) else 1


if __name__ == '__main__':
    raise SystemExit(main())

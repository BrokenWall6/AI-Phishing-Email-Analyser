import os
import sys

BASE_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..")
)

# make "import app" work when pytest is run from any folder
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

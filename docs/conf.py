"""Sphinx configuration for pyrxd documentation.

Builds the public-facing docs at https://pyrxd.readthedocs.io. Favours
clarity and zero-warning builds over feature breadth.
"""
from __future__ import annotations

import os
import sys
from datetime import datetime

# Make `import pyrxd` work for autodoc.
sys.path.insert(0, os.path.abspath("../src"))

# -- Project information --

project = "pyrxd"
author = "Mudwood Labs"
copyright = f"{datetime.now().year}, {author}"

# Read the version from the package itself so docs and code never drift.
from pyrxd import __version__ as _pyrxd_version  # noqa: E402

version = _pyrxd_version
release = _pyrxd_version

# -- General configuration --

extensions = [
    "sphinx.ext.autodoc",
    "sphinx.ext.napoleon",
    "sphinx.ext.viewcode",
    "sphinx.ext.intersphinx",
    "myst_parser",
]

source_suffix = {
    ".rst": "restructuredtext",
    ".md": "markdown",
}

templates_path = ["_templates"]
exclude_patterns = ["_build", "Thumbs.db", ".DS_Store"]

# -- Autodoc --

autodoc_default_options = {
    "members": True,
    "member-order": "bysource",
    "undoc-members": False,
    "show-inheritance": True,
}
autodoc_typehints = "description"
autodoc_class_signature = "separated"

# -- Napoleon (Google / NumPy style docstrings) --

napoleon_google_docstring = True
napoleon_numpy_docstring = True
napoleon_include_init_with_doc = True

# -- Intersphinx --

intersphinx_mapping = {
    "python": ("https://docs.python.org/3", None),
}

# -- HTML --

html_theme = "furo"
html_title = f"pyrxd {version}"
html_static_path = ["_static"]
html_theme_options = {
    "source_repository": "https://github.com/MudwoodLabs/pyrxd",
    "source_branch": "main",
    "source_directory": "docs/",
}

# -- MyST --

myst_enable_extensions = [
    "colon_fence",
    "deflist",
    "smartquotes",
]

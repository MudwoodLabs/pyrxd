# Configuration file for the Sphinx documentation builder.
#
# This file only contains a selection of the most common options. For a full
# list see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html

# -- Path setup --------------------------------------------------------------

# If extensions (or modules to document with autodoc) are in another directory,
# add these directories to sys.path here. If the directory is relative to the
# documentation root, use os.path.abspath to make it absolute, like shown here.
#
import os
import sys
import tomli

sys.path.insert(0, os.path.abspath("../src/"))

# Read project configuration from pyproject.toml
with open("../pyproject.toml", "rb") as f:
    pyproject = tomli.load(f)

# -- Project information -----------------------------------------------------
sphinx_config = pyproject["tool"]["sphinx"]

project = sphinx_config["project"]
copyright = sphinx_config["copyright"]
author = sphinx_config["author"]
version = sphinx_config["version"]
release = sphinx_config["release"]

# -- General configuration ---------------------------------------------------
extensions = sphinx_config["extensions"]
templates_path = sphinx_config["templates_path"]
exclude_patterns = sphinx_config["exclude_patterns"]

# -- Options for HTML output -------------------------------------------------
html_theme = sphinx_config["html_theme"]
html_static_path = sphinx_config["html_static_path"]

# Napoleon settings
napoleon_include_init_with_doc = sphinx_config["napoleon_include_init_with_doc"]
napoleon_include_private_with_doc = sphinx_config["napoleon_include_private_with_doc"]

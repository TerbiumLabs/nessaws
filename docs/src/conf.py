# -*- coding: utf-8 -*-
import pkg_resources


author = u'Terbium Labs'
copyright = u'2017, Terbium Labs'
exclude_patterns = []
extensions = [
    'sphinx.ext.autodoc',
    'sphinx.ext.autosectionlabel',
    'sphinx.ext.doctest',
    'sphinx.ext.intersphinx',
    'sphinx.ext.todo',
    'sphinx.ext.coverage',
    'sphinx.ext.viewcode',
    'sphinxcontrib.napoleon',
]
html_static_path = ['_static']
html_theme = 'material_design'
html_theme_options = {}
intersphinx_mapping = {
    'https://docs.python.org/': None,
}
master_doc = 'index'
project = u'nessaws'
pygments_style = 'sphinx'
release = version = pkg_resources.get_distribution(
    'nessaws').version
source_suffix = '.rst'
templates_path = ['_templates']
todo_include_todos = True

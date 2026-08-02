"""ExternalAuthenticator version info.

The single source of truth for the version. pyproject.toml reads it via
[tool.setuptools.dynamic], so bumping the tuple below is the only edit a
release needs.
"""

# Copyright (c) Michael Albert.
# Distributed under the terms of the Modified BSD License.

version_info = (
    1,
    0,
    1,
    # 'dev',  # uncomment this line for a development version
)
__version__ = '.'.join(map(str, version_info[:3]))

if len(version_info) > 3:
    __version__ = '%s%s' % (__version__, version_info[3])

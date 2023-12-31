# -*- coding: utf-8 -*-
#
# Copyright (c) nexB Inc. and others. All rights reserved.
# ScanCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/scancode-plugins for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import logging
import os

from commoncode import command
from commoncode import fileutils
from commoncode.functional import flatten

from plugincode.location_provider import get_location

SOURCE_INSPECTOR_CTAGS_EXE = "source_inspector.ctags.exe"
SOURCE_INSPECTOR_CTAGS_LIB = "source_inspector.ctags.lib"

"""
Extract symbols information from source code files with ctags.
"""
LOG = logging.getLogger(__name__)

bin_dir = os.path.join(os.path.dirname(__file__), "bin")


class Source:
    """
    Source code object.
    """

    def __init__(self, sourcefile):
        # yield nothing if we do not have a proper command
        self.sourcefile = sourcefile

        self.cmd_loc = get_location(SOURCE_INSPECTOR_CTAGS_EXE)
        self.lib_loc = get_location(SOURCE_INSPECTOR_CTAGS_LIB)

        # nb: those attributes names are api and expected when fingerprinting
        # a list of sources files names (not path)
        self.files = []
        self.files.append(fileutils.file_name(sourcefile))
        # a list of function names
        self.local_functions = []
        self.global_functions = []

        self._collect_and_parse_tags()

    def symbols(self):
        glocal = flatten([self.local_functions, self.global_functions])
        return sorted(glocal)

    def _collect_and_parse_tags(self):
        ctags_args = ["--fields=K", "--c-kinds=fp", "-f", "-", self.sourcefile]
        ctags_temp_dir = fileutils.get_temp_dir(base_dir="ctags")
        envt = {"TMPDIR": ctags_temp_dir}
        try:
            rc, stdo, err = command.execute2(
                cmd_loc=self.cmd_loc,
                cmd_args=ctags_args,
                env=envt,
                lib_dir=self.lib_loc,
                to_files=True,
            )

            if rc != 0:
                raise Exception(open(err).read())

            with open(stdo, "rb") as lines:
                for line in lines:
                    if "cannot open temporary file" in line:
                        raise Exception("ctags: cannot open temporary file " ": Permission denied")

                    if line.startswith("!"):
                        continue

                    line = line.strip()
                    if not line:
                        continue

                    splitted = line.split("\t")

                    if line.endswith("function\tfile:") or line.endswith("prototype\tfile:"):
                        self.local_functions.append(splitted[0])

                    elif line.endswith("function") or line.endswith("prototype"):
                        self.global_functions.append(splitted[0])
        finally:
            fileutils.delete(ctags_temp_dir)

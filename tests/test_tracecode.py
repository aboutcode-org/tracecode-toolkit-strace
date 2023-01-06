#!/usr/bin/env python
# -*- coding: utf8 -*-
#
# Copyright (c) nexB Inc. and others. All rights reserved.
# ScanCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/tracecode-toolkit-strace for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import collections
import csv
import logging
import multiprocessing
import os
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import unittest
from os.path import dirname
from os.path import join
from pathlib import Path
from queue import Empty as Queue_Empty
from queue import Queue

import pytest

from tracecode import conf
from tracecode import pathutils
from tracecode import tracecode

# used only for pickle
from tracecode.tracecode import Exec  # @UnusedImport
from tracecode.tracecode import Process  # @UnusedImport
from tracecode.tracecode import Readwrite  # @UnusedImport
from tracecode.tracecode import as_graph

ROOT_DIR = dirname(dirname(os.path.abspath(__file__)))
BASE_DIR = join(ROOT_DIR, "tests", "data")

logger = logging.getLogger("tracecode")

# set to True temporarily to force a global regeneration of expectations based
# on actual results. Use with caution. Do not commit with True
_GLOBAL_REGEN = False

"""The conventions used for the tracecode tests are:
- for tests that require files these are stored in the test_data directory

- tests that create temp files should clean up after themselves. Call
self.to_clean(path_to_clean) to have this done for you automatically

- each test must use its own sub directory in test_data. The is is called the
'base'

- test data files that are more than a few KB should be in a bzip2 tarball

- for tests that require traces, the convention is to have a trace-
archive.tar.bz2 file under the base. Calling self.extract(base) will extract
this and return the temp directory where this was extracted. This temp dir will
be deleted after the test run automatically.
"""

sys_platform = str(sys.platform).lower()
on_linux = sys_platform.startswith('linux')
on_windows = 'win32' in sys_platform


def to_os_native_path(s):
    """Normalize a path to use the native OS path separator."""
    return s.replace("/", os.path.sep).replace("\\", os.path.sep).rstrip(os.path.sep)


class BaseTestCase(unittest.TestCase):

    def setUp(self):
        if not hasattr(self, "to_delete"):
            self.to_delete = []

    def tearDown(self):
        for loc in self.to_delete:
            self.make_rwe(loc)
            shutil.rmtree(loc, ignore_errors=True)

    def set_rwe(self, location):
        try:
            # u+rwx g+rx o+rx
            os.chmod(
                location, stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH
            )
        except OSError:
            pass

    def make_rwe(self, location):
        """
        Make all the files in location user readable, writable and executable.
        """
        if not os.path.exists(location):
            return
        if not os.path.isdir(location):
            self.set_rwe(location)
            return
        for pth, _, files in os.walk(location):
            for f in files:
                self.set_rwe(join(pth, f))

    def extract_trace(self, base, delete=True):
        """
        Extract a trace archive located in a conventional place. Return the
        temporary dir where the trace was extracted. The temporary dir is
        deleted once tests are completed.
        If base = 'mytrace', then the archive is located in:
            test_data/mytrace/trace-archive.tar.bz2
        Then the root dir of that archive is 'trace'.
        """
        input_tar = join(self.get_tst_path(base), "trace-archive.tar.bz2")
        extract_dir = self.extract_archive(input_tar, delete)
        return join(extract_dir, "trace")

    def extract_archive(self, location, delete=True):
        """
        Extract a tar.bz2 archive located at location. Return the temporary dir
        where the trace was extracted. The temporary dir is deleted once tests
        are completed.
        """
        with open(location, "rb") as input_tar:
            tar = tarfile.open(fileobj=input_tar)
            extract_dir = self.get_temp_dir(delete)
            tar.extractall(extract_dir)
            self.make_rwe(extract_dir)

            return extract_dir

    def build_archive(self, real_path, tar_path, outarch):
        from contextlib import closing

        with closing(tarfile.open(outarch, mode="w:bz2")) as out:
            out.add(real_path, arcname=tar_path)

    def get_tst_path(self, dirpath):
        dp = to_os_native_path(dirpath)
        return join(BASE_DIR, dp)

    def get_temp_dir(self, delete=True):
        assert dir and dir != ""
        tmp = tempfile.mkdtemp(suffix="", prefix="tracecode-tests-")
        if delete:
            self.to_delete.append(tmp)
        return tmp

    def regen_pformats(self, test_name, procs):
        tmp = self.get_temp_dir()
        tar_dir = "expected_pformats"
        for proc in procs:
            fn = join(tmp, str(proc.pid))
            with open(fn) as fout:
                fout.write(proc.pformat())
        expected_pf = self.get_tst_path(join(test_name, "expected_pformats.tar.bz2"))
        self.build_archive(tmp, tar_dir, expected_pf)

    def check_pformats(
        self,
        test_name,
        cwd,
        with_output_dir=False,
        clean=False,
        parallel=False,
        regen=False,
        settings=None,
    ):
        """
        Perform a relatively complex test where a trace archive is extracted
        and processed Then an archive of saved pformats representation for each
        processed is loaded and tested against the current pformat
        representation for each proc. Optionally saves the parsing to
        output_dir, runs in parallel and regen the expected pformats files
        """
        input_dir = self.extract_trace(test_name)
        output_dir = None
        if with_output_dir:
            output_dir = self.get_temp_dir()
        if not settings:
            stgs = conf.DefaultSettings()
        else:
            stgs = settings

        procs = tracecode.parse_raw_traces(
            cwd, input_dir, output_dir, parallel=parallel, settings=stgs, clean=clean
        )
        if with_output_dir:
            procs = tracecode.load(output_dir, procs)

        if regen or _GLOBAL_REGEN:
            self.regen_pformats(test_name, procs)
        ar = self.get_tst_path(join(test_name, "expected_pformats.tar.bz2"))
        expected_pf = join(self.extract_archive(ar), "expected_pformats")
        for proc in procs:
            fn = join(expected_pf, str(proc.pid))
            with open(fn) as fin:
                expected = fin.read().splitlines()
                assert expected == proc.pformat().splitlines()

    def run_tracecode_command(self, args, cwd=ROOT_DIR):
        args = args or []
        args = ["venv/bin/tracecode"] + args
        try:
            return subprocess.check_output(args, cwd=cwd)
        except subprocess.CalledProcessError as e:
            raise Exception(" ".join(args), e.output) from e


class BasicTest(BaseTestCase):

    def test_validate_traces(self):
        trace_dir = self.extract_trace("validate")
        rootpid, traces = tracecode.validate_traces(trace_dir)
        assert 2453402 == rootpid
        assert 132 == len(traces)
        assert traces[2453402].endswith("strace.2453402")

    def test_validate_traces_with_inconsistent_trace_names_should_raise_exception(self):
        trace_dir = self.get_tst_path("strace2/trace")
        self.assertRaises(AssertionError, tracecode.validate_traces, trace_dir)

    def test_validate_traces_with_non_file_in_trace_inputdir_should_raise_exception(self):
        trace_dir = self.get_tst_path("strace3/trace")
        self.assertRaises(AssertionError, tracecode.validate_traces, trace_dir)

    def test_validate_traces_can_find_root_with_pid_rollover(self):
        trace_dir = self.extract_trace("validate_out_of_order")
        rootpid, _traces = tracecode.validate_traces(trace_dir)
        assert 2800285 == rootpid

    def test_parse_entry(self):
        expected = [
            tracecode.Entry(
                tstamp="1389171522.375781",
                result="0",
                func="execve",
                args=["/usr/bin/make", "make"],
            ),
            tracecode.Entry(
                tstamp="1389171522.376446",
                result="4",
                func="open",
                args=["/lib/x86_64-linux-gnu/libc.so.6", "O_RDONLY|O_CLOEXEC"],
            ),
            tracecode.Entry(
                tstamp="1389171522.376468",
                result="832",
                func="read",
                args=["4</lib/x86_64-linux-gnu/libc-2.15.so>", "\\177ELF\\2\\1\\1...", "832"],
            ),
            tracecode.Entry(
                tstamp="1389171522.376782",
                result="0",
                func="arch_prctl",
                args=["ARCH_SET_FS", "0x7ff784398700"],
            ),
            tracecode.Entry(
                tstamp="1389171522.377455",
                result="35",
                func="getcwd",
                args=["/home/nexb/tools/strace/strace-4.8", "4096"],
            ),
            tracecode.Entry(
                tstamp="1389171522.377657",
                result="4",
                func="openat",
                args=["AT_FDCWD", ".", "O_RDONLY|O_NONBLOCK|O_DIRECTORY|O_CLOEXEC"],
            ),
            tracecode.Entry(
                tstamp="1389171522.377780", result="4", func="open", args=["Makefile", "O_RDONLY"]
            ),
            tracecode.Entry(
                tstamp="1389171522.392265",
                result="4",
                func="openat",
                args=["AT_FDCWD", "linux/x86_64", "O_RDONLY|O_NONBLOCK|O_DIRECTORY|O_CLOEXEC"],
            ),
            tracecode.Entry(
                tstamp="1389171522.392467",
                result="22",
                func="write",
                args=["1</dev/pts/6>", "/bin/mkdir -p ./linux\\n", "22"],
            ),
            tracecode.Entry(tstamp="1389171522.392584", result="2453403", func="vfork", args=[]),
            tracecode.Entry(
                tstamp="1389171528.651642",
                result="0",
                func="chdir",
                args=["/home/nexb/tools/strace/strace-4.8"],
            ),
            tracecode.Entry(
                tstamp="1390356496.673733",
                result="0",
                func="execve",
                args=[
                    "/usr/lib/gcc/x86_64-linux-gnu/4.6/cc1",
                    "/usr/lib/gcc/x86_64-linux-gnu/4....",
                    "-quiet",
                    "-I",
                    ".",
                    "-I",
                    ".",
                    "-I",
                    "./include",
                    "-I",
                    "./lib",
                    "-imultilib",
                    ".",
                    "-imultiarch",
                    "x86_64-linux-gnu",
                    "-D",
                    'PROGRAM="bash"',
                    "...",
                ],
            ),
        ]
        with open(self.get_tst_path("parse_entry/basic.trace")) as inf:
            result = [tracecode.parse_entry(l.strip()) for l in inf]
            assert expected == result

    def test_parse_entry_dup(self):
        line = "1390356525.416370 dup(4<pipe:[8091470]>)           = 6"
        expected = tracecode.Entry(
            tstamp="1390356525.416370", result="6", func="dup", args=["4<pipe:[8091470]>"]
        )
        result = tracecode.parse_entry(line)
        assert expected == result

    def test_parse_entry_dup2(self):
        line = "1390356525.416370 dup2(9<pipe:[8060]>, 1<pipe:[8058]>) = 1"
        expected = tracecode.Entry(
            tstamp="1390356525.416370",
            result="1",
            func="dup2",
            args=["9<pipe:[8060]>", "1<pipe:[8058]>"],
        )
        result = tracecode.parse_entry(line)
        assert expected == result

    def test_parse_entry_dup3(self):
        line = "1390356525.416370 dup3(4</s/str.c>, 0<pipe:[8087]>, 0 ) = 1"
        expected = tracecode.Entry(
            tstamp="1390356525.416370",
            result="1",
            func="dup3",
            args=["4</s/str.c>", "0<pipe:[8087]>", "0"],
        )
        result = tracecode.parse_entry(line)
        assert expected == result

    def test_parse_entry_resolve_descriptor_with_deleted_descriptor(self):
        line = '1390356525.416370 read(0</tmp/sh-thd-1391680596 (deleted)>, "#include <libintl.h>\nint main( deleted)\n"..., 61) = 61'
        expected = tracecode.Entry(
            tstamp="1390356525.416370",
            result="61",
            func="read",
            args=[
                "0</tmp/sh-thd-1391680596>",
                "#include <libintl.h>\nint main( deleted)\n...",
                "61",
            ],
        )
        result = tracecode.parse_entry(line)
        assert repr(expected) == repr(result)
        tracecode.resolve_descriptors(result)
        expected2 = tracecode.Entry(
            tstamp="1390356525.416370",
            result="61",
            func="read",
            args=["/tmp/sh-thd-1391680596", "#include <libintl.h>\nint main( deleted)\n...", "61"],
        )
        assert expected2 == result

    def test_parse_entry_with_space_in_paths(self):
        expected = [
            tracecode.Entry(
                tstamp="1389171522.375781",
                result="0",
                func="execve",
                args=["/usr/bin/ma ke", "make"],
            ),
            tracecode.Entry(
                tstamp="1389171522.376446",
                result="4",
                func="open",
                args=["/lib/x86_64-linux  -gnu/libc.so.6", "O_RDONLY|O_CLOEXEC"],
            ),
            tracecode.Entry(
                tstamp="1389171522.376468",
                result="832",
                func="read",
                args=["4</lib/x86_64-linux  -gnu/libc-2.15.so>", "\\177ELF\\2\\1\\1...", "832"],
            ),
            tracecode.Entry(
                tstamp="1389171522.376782",
                result="0",
                func="arch_prctl",
                args=["ARCH_SET_FS", "0x7ff784398700"],
            ),
            tracecode.Entry(
                tstamp="1389171522.377455",
                result="35",
                func="getcwd",
                args=["/home/nexb/tools/str  ace/strace-4.8", "4096"],
            ),
            tracecode.Entry(
                tstamp="1389171522.377657",
                result="4",
                func="openat",
                args=["AT_FDCWD", "some path", "O_RDONLY|O_NONBLOCK|O_DIRECTORY|O_CLOEXEC"],
            ),
            tracecode.Entry(
                tstamp="1389171522.377780", result="4", func="open", args=["Makefile", "O_RDONLY"]
            ),
            tracecode.Entry(
                tstamp="1389171522.392265",
                result="4",
                func="openat",
                args=["AT_FDCWD", "lin  ux/x86_64", "O_RDONLY|O_NONBLOCK|O_DIRECTORY|O_CLOEXEC"],
            ),
            tracecode.Entry(
                tstamp="1389171522.392467",
                result="22",
                func="write",
                args=["1</dev/p  ts/6>", "/bin/mkdir -p ./linux\\n", "22"],
            ),
            tracecode.Entry(tstamp="1389171522.392584", result="2453403", func="vfork", args=[]),
            tracecode.Entry(
                tstamp="1389171528.651642",
                result="0",
                func="chdir",
                args=["/home/nexb/tools/str  ace/strace-4.8"],
            ),
            tracecode.Entry(
                tstamp="1390356496.673733",
                result="0",
                func="execve",
                args=[
                    "/usr/lib/gcc/x86  _64-linux-gnu/4.6/cc1",
                    "/usr/lib/gcc/x86_64-linux-gnu/4....",
                    "-quiet",
                    "-I",
                    ".",
                    "-I",
                    ".",
                    "-I",
                    "./include",
                    "-I",
                    "./lib",
                    "-imultilib",
                    ".",
                    "-imultiarch",
                    "x86_64-linux-gnu",
                    "-D",
                    'PROGRAM="bash"',
                    "...",
                ],
            ),
        ]
        with open(self.get_tst_path("parse_entry/space.trace")) as inf:
            result = [tracecode.parse_entry(l.strip()) for l in inf]
            assert expected == result

    def test_parse_trace_file_minitrace(self):
        input_dir = self.get_tst_path("strace_mini/trace")
        trace_file = join(input_dir, "strace.2453402")
        proc = tracecode.Process(pid=2453402, ppid=None, cwd="/")

        todo = multiprocessing.Queue()
        done = multiprocessing.Queue()

        tracecode.parse_trace_file(proc, trace_file, todo, done)

        dproc = done.get()
        assert proc.pid == dproc.pid
        assert 2453403 == sorted(proc.children.keys())[0]

        child = todo.get()
        assert 2453403 == child.pid

        trace_file2 = join(input_dir, "strace.2453403")
        tracecode.parse_trace_file(child, trace_file2, todo, done)
        dchild = done.get()
        assert child.pid == dchild.pid
        assert 2453403 == dchild.pid
        assert 2453402 == dchild.ppid
        assert {} == child.children

    def test_parse_raw_traces_mini2(self):
        input_dir = self.get_tst_path("strace_mini2/trace")
        output_dir = None
        cwd = "/"
        done = tracecode.parse_raw_traces(cwd, input_dir, output_dir, parallel=False, clean=False)
        root = done[0]
        assert 2453402 == root.pid
        child = done[1]
        assert 2453403 == child.pid

    def test_ignored_lines(self):
        lines = [
            l.strip()
            for l in """1389171522.418917 open("/usr/share/locale/en_US.UTF-8/LC_MESSAGES/gcc-4.6.mo", O_RDONLY) = -1 ENOENT (No such file or directory)
    1389171522.396437 mkdir("linux", 0775) = -1 EEXIST (File exists)
    1389171528.651576 --- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_EXITED, si_pid=2453412, si_status=0, si_utime=1, si_stime=0} ---
    1389171528.651839 +++ exited with 0 +++""".splitlines()
        ]
        for l in lines:
            haserr = tracecode.has_error(l, conf.DefaultSettings().errors)
            assert haserr

    def test_decode_args_can_decode_simple_args(self):
        # list of tuple (input args strings, expected decoded args list,)
        tests = [
            (
                r"""4</lib/x86_64-linux-gnu/libtinfo.so.5.9>, "\177ELF\2\1\310-\"\0\0\0\0\0\310-\"\0\0\0\0\0X8\0\0"..., 832""",
                [
                    "4</lib/x86_64-linux-gnu/libtinfo.so.5.9>",
                    '\\177ELF\\2\\1\\310-"\\0\\0\\0\\0\\0\\310-"\\0\\0\\0\\0\\0X8\\0\\0...',
                    "832",
                ],
            ),
            (
                r"""4</tmp/ccGJ3nlX.s>, "ue\t0x1\n\t.byte\t0x55\n\t.quad\t.LVL10-.Ltext0\n\t.value\t0x1\n"..., 4096""",
                [
                    "4</tmp/ccGJ3nlX.s>",
                    "ue\\t0x1\\n\\t.byte\\t0x55\\n\\t.quad\\t.LVL10-.Ltext0\\n\\t.value\\t0x1\\n...",
                    "4096",
                ],
            ),
            (
                r"""4</tmp/ccGJ3nlX.s>, "g\t\"u_error\"\t\"doth\"\n.\"short int\"\n\"m\"\n.LASF7:\"__off_t\"\n.LA"..., 993""",
                [
                    "4</tmp/ccGJ3nlX.s>",
                    'g\\t"u_error"\\t"doth"\\n."short int"\\n"m"\\n.LASF7:"__off_t"\\n.LA...',
                    "993",
                ],
            ),
            (r'''".deps/system.Tpo", ".deps/system.Po"''', [".deps/system.Tpo", ".deps/system.Po"]),
        ]
        for args, expected in tests:
            dec = tracecode.decode_args(args)
            assert expected == dec

    def test_decode_args_can_decode_path_args_with_spaces(self):
        # list of tuple (input args strings, expected decoded args list,)
        tests = [
            (
                r"""4</lib/x86_64-linux  -gnu/libtinfo.so.5.9>, "\177ELF\2\1\310-\"\0\0\0\0\0\310-\"\0\0\0\0\0X8\0\0"..., 832""",
                [
                    "4</lib/x86_64-linux  -gnu/libtinfo.so.5.9>",
                    '\\177ELF\\2\\1\\310-"\\0\\0\\0\\0\\0\\310-"\\0\\0\\0\\0\\0X8\\0\\0...',
                    "832",
                ],
            ),
            (
                r"""4</tmp/cc  GJ3nlX.s>, "ue\t0x1\n\t.byte\t0x55\n\t.quad\t.LVL10-.Ltext0\n\t.value\t0x1\n"..., 4096""",
                [
                    "4</tmp/cc  GJ3nlX.s>",
                    "ue\\t0x1\\n\\t.byte\\t0x55\\n\\t.quad\\t.LVL10-.Ltext0\\n\\t.value\\t0x1\\n...",
                    "4096",
                ],
            ),
            (
                r"""4</tmp/cc  GJ3nlX.s>, "g\t\"u_error\"\t\"doth\"\n.\"short int\"\n\"m\"\n.LASF7:\"__off_t\"\n.LA"..., 993""",
                [
                    "4</tmp/cc  GJ3nlX.s>",
                    'g\\t"u_error"\\t"doth"\\n."short int"\\n"m"\\n.LASF7:"__off_t"\\n.LA...',
                    "993",
                ],
            ),
            (
                r'''".deps/sys  tem.Tpo", ".deps/sy  stem.Po"''',
                [".deps/sys  tem.Tpo", ".deps/sy  stem.Po"],
            ),
        ]
        for args, expected in tests:
            dec = tracecode.decode_args(args)
            assert expected == dec

    def test_decode_args_can_decode_path_args_with_commas(self):
        # list of tuple (input args strings, expected decoded args list,)
        tests = [
            (
                r"""4</lib/x86_64-linux,-gnu/libtinfo.so.5.9>, "\177ELF\2\1\310-\"\0\0\0\0\0\310-\"\0\0\0\0\0X8\0\0"..., 832""",
                [
                    "4</lib/x86_64-linux,-gnu/libtinfo.so.5.9>",
                    '\\177ELF\\2\\1\\310-"\\0\\0\\0\\0\\0\\310-"\\0\\0\\0\\0\\0X8\\0\\0...',
                    "832",
                ],
            ),
            (
                r"""4</tmp/cc,GJ3nlX.s>, "ue\t0x1\n\t.byte\t0x55\n\t.quad\t.LVL10-.Ltext0\n\t.value\t0x1\n"..., 4096""",
                [
                    "4</tmp/cc,GJ3nlX.s>",
                    "ue\\t0x1\\n\\t.byte\\t0x55\\n\\t.quad\\t.LVL10-.Ltext0\\n\\t.value\\t0x1\\n...",
                    "4096",
                ],
            ),
            (
                r"""4</tmp/cc,GJ3nlX.s>, "g\t\"u_error\"\t\"doth\"\n.\"short int\"\n\"m\"\n.LASF7:\"__off_t\"\n.LA"..., 993""",
                [
                    "4</tmp/cc,GJ3nlX.s>",
                    'g\\t"u_error"\\t"doth"\\n."short int"\\n"m"\\n.LASF7:"__off_t"\\n.LA...',
                    "993",
                ],
            ),
            (
                r'''".deps/sys,tem.Tpo", ".deps/sy,stem.Po"''',
                [".deps/sys,tem.Tpo", ".deps/sy,stem.Po"],
            ),
        ]
        for args, expected in tests:
            dec = tracecode.decode_args(args)
            assert expected == dec

    def test_decode_args_can_decode_path_args_with_weird_fd_like_strings(self):
        # list of tuple (input args strings, expected decoded args list,)
        tests = [
            (
                r"""3</cups/adminutil.o>, "les...\\n\\0<Location /admin/conf>\\n "..., 4096""",
                ["3</cups/adminutil.o>", "les...\\n\\0<Location /admin/conf>\\n ...", "4096"],
            ),
            (
                r"""4</cgi-bin/websearch>, "\\327\\362\\256\\200;<H\\367\\321L\\215d\\n\\376u\\31A\\200<$>t\\nH\\307E\\0\\0\\0\\0\\0\\353"..., 4096""",
                [
                    "4</cgi-bin/websearch>",
                    "\\327\\362\\256\\200;<H\\367\\321L\\215d\\n\\376u\\31A\\200<$>t\\nH\\307E\\0\\0\\0\\0\\0\\353...",
                    "4096",
                ],
            ),
        ]
        for args, expected in tests:
            dec = tracecode.decode_args(args)
            assert expected == dec

    def test_decode_args_can_decode_path_args_with_simple_descriptors(self):
        # list of tuple (input args strings, expected decoded args list,)
        tests = [
            ("3</bash-4.1/pathnames.tmp>, 1", ["3</bash-4.1/pathnames.tmp>", "1"]),
            ("3</bash-4.1/.made>, 1", ["3</bash-4.1/.made>", "1"]),
            ("3</bash-4.1/.build>, 1", ["3</bash-4.1/.build>", "1"]),
            ("3</dev/null>, 2", ["3</dev/null>", "2"]),
            ("3</bash-4.1/builtins/pipesize.h>, 1", ["3</bash-4.1/builtins/pipesize.h>", "1"]),
            ("3</tmp/pipsize.AdzIOk>, 2", ["3</tmp/pipsize.AdzIOk>", "2"]),
        ]
        for args, expected in tests:
            dec = tracecode.decode_args(args)
            assert expected == dec

    def test_decode_descriptor(self):
        tests = [
            ("4</lib/x86_64-linux-gnu/libtinfo.so.5.9>", "/lib/x86_64-linux-gnu/libtinfo.so.5.9"),
            ("4</tmp/ccGJ3nlX.s>", "/tmp/ccGJ3nlX.s"),
            ("4<../tmp/ccG\\>J3nlX.s>", "../tmp/ccG\\>J3nlX.s"),
            ("AT_FDCWD", "AT_FDCWD"),
        ]
        for s, expected in tests:
            dec = tracecode.decode_descriptor(s)
            assert expected == dec

    def test_resolve_paths_with_execve(self):
        cwd = "/TEST/"
        entry = """1389098234.445561 execve("prebuilts/tools/gcc-sdk/../../gcc/bin/i686-linux-gcc", ["prebuilts/tools/gcc-sdk/../../gcc/linux-x86/host/i686-linux-glibc2.7-4.6/bin/i686-linux-gcc", "-I", "external/libsepol/include/", "-I", "external/libsepol/src/", "-I", "external/libsepol", "-I", "out/host/linux-x86/obj/STATIC_LIBRARIES/libsepol_intermediates", "-I", "libnativehelper/include/nativehelper", "-isystem", "system/core/include", "-isystem", "hardware/libhardware/include", "-isystem", "hardware/libhardware_legacy/include", "-isystem", "hardware/ril/include", "-isystem", "libnativehelper/include", "-isystem", "frameworks/native/include", "-isystem", "frameworks/native/opengl/include", "-isystem", "frameworks/av/include", "-isystem", "frameworks/base/include", "-isystem", "external/skia/include", "-isystem", "tools/include", "-isystem", "out/host/linux-x86/obj/include", "-c", "-fno-exceptions", "-Wno-multichar", "-mstackrealign", "-msse3", "-mfpmath=sse", "-m32", "-fPIC", "-include", "build/core/combo/include/arch/linux-x86/AndroidConfig.h", "-U_FORTIFY_SOURCE", "-D_FORTIFY_SOURCE=0", "-DANDROID", "-fmessage-length=0", "-W", "-Wall", "-Wno-unused", "-Winit-self", "-Wpointer-arith", "-O2", "-g", "-fno-strict-aliasing", "-DNDEBUG", "-UDEBUG", "-Wall", "-W", "-Wundef", "-Wshadow", "-Wmissing-noreturn", "-Wmissing-format-attribute", "-MD", "-MF", "out/host/linux-x86/obj/STATIC_LIBRARIES/libsepol_intermediates/src/port_record.d", "-o", "out/host/linux-x86/obj/STATIC_LIBRARIES/libsepol_intermediates/src/port_record.o", "external/libsepol/src/port_record.c"], [/* 65 vars */]) = 0"""
        e = tracecode.parse_entry(entry)
        er = tracecode.resolve_paths(e, cwd)
        expected = "/TEST/prebuilts/gcc/bin/i686-linux-gcc"
        assert expected == er.args[0]

    def test_resolve_paths_with_rename(self):
        cwd = "/TEST/"
        entry = (
            '1389098994.521748 rename("./net/core/.filter.o.tmp", "/net/core/.filter.o.cmd") = 0'
        )
        e = tracecode.parse_entry(entry)
        er = tracecode.resolve_paths(e, cwd)
        assert "/TEST/net/core/.filter.o.tmp" == er.args[0]
        assert "/net/core/.filter.o.cmd" == er.args[1]

    def test_resolve_paths_empty_cwd(self):
        cwd = None
        entry = """1389098234.445561 execve("prebuilts/tools/gcc-sdk/../../gcc/bin/i686-linux-gcc", ["prebuilts/tools/gcc-sdk/../../gcc/linux-x86/host/i686-linux-glibc2.7-4.6/bin/i686-linux-gcc", "-I", "external/libsepol/include/", "-I", "external/libsepol/src/", "-I", "external/libsepol", "-I", "out/host/linux-x86/obj/STATIC_LIBRARIES/libsepol_intermediates", "-I", "libnativehelper/include/nativehelper", "-isystem", "system/core/include", "-isystem", "hardware/libhardware/include", "-isystem", "hardware/libhardware_legacy/include", "-isystem", "hardware/ril/include", "-isystem", "libnativehelper/include", "-isystem", "frameworks/native/include", "-isystem", "frameworks/native/opengl/include", "-isystem", "frameworks/av/include", "-isystem", "frameworks/base/include", "-isystem", "external/skia/include", "-isystem", "tools/include", "-isystem", "out/host/linux-x86/obj/include", "-c", "-fno-exceptions", "-Wno-multichar", "-mstackrealign", "-msse3", "-mfpmath=sse", "-m32", "-fPIC", "-include", "build/core/combo/include/arch/linux-x86/AndroidConfig.h", "-U_FORTIFY_SOURCE", "-D_FORTIFY_SOURCE=0", "-DANDROID", "-fmessage-length=0", "-W", "-Wall", "-Wno-unused", "-Winit-self", "-Wpointer-arith", "-O2", "-g", "-fno-strict-aliasing", "-DNDEBUG", "-UDEBUG", "-Wall", "-W", "-Wundef", "-Wshadow", "-Wmissing-noreturn", "-Wmissing-format-attribute", "-MD", "-MF", "out/host/linux-x86/obj/STATIC_LIBRARIES/libsepol_intermediates/src/port_record.d", "-o", "out/host/linux-x86/obj/STATIC_LIBRARIES/libsepol_intermediates/src/port_record.o", "external/libsepol/src/port_record.c"], [/* 65 vars */]) = 0"""
        e = tracecode.parse_entry(entry)
        er = tracecode.resolve_paths(e, cwd)
        assert "prebuilts/gcc/bin/i686-linux-gcc" == er.args[0]

    def test_resolve_openat_with_AT_FDCWD(self):
        cwd = "/TEST/"
        entry = """1412060539.019194 openat(AT_FDCWD, "openssl-0.9.8y/test/rc4test.c", O_WRONLY|O_CREAT|O_EXCL, 0) = 4"""
        e = tracecode.parse_entry(entry)
        er = tracecode.resolve_paths(e, cwd)
        assert "/TEST/openssl-0.9.8y/test/rc4test.c" == er.args[0]

    def test_resolve_openat_with_regular_file_descriptor(self):
        cwd = "/TEST/"
        entry = """1412060539.019194 openat(5</extra/>, "openssl-0.9.8y/test/rc4test.c", O_WRONLY|O_CREAT|O_EXCL, 0) = 4"""
        e = tracecode.parse_entry(entry)
        tracecode.resolve_descriptors(e, True)
        er = tracecode.resolve_paths(e, cwd)
        assert "/extra/openssl-0.9.8y/test/rc4test.c" == er.args[0]

    def test_resolve_openat_with_absolute_path(self):
        cwd = "/TEST/"
        entry = """1412060539.019194 openat(AT_FDCWD, "/absolute/openssl-0.9.8y/test/rc4test.c", O_WRONLY|O_CREAT|O_EXCL, 0) = 4"""
        e = tracecode.parse_entry(entry)
        tracecode.resolve_descriptors(e, True)
        er = tracecode.resolve_paths(e, cwd)
        assert "/absolute/openssl-0.9.8y/test/rc4test.c" == er.args[0]

    def test_resolve_symlinkat_with_AT_FDCWD(self):
        cwd = "/TEST/"
        entry = """1412060539.019122 symlinkat("dummytest.c", AT_FDCWD, "openssl-0.9.8y/test/rc5test.c") = 0"""
        e = tracecode.parse_entry(entry)
        tracecode.resolve_descriptors(e, True)
        er = tracecode.resolve_paths(e, cwd)
        assert "/TEST/dummytest.c" == er.args[0]
        assert "/TEST/openssl-0.9.8y/test/rc5test.c" == er.args[1]

    def test_resolve_symlinkat_with_regular_file_descriptor(self):
        cwd = "/TEST/"
        entry = """1412060539.019122 symlinkat("dummytest.c", 5</extra/>, "openssl-0.9.8y/test/rc5test.c") = 0"""
        e = tracecode.parse_entry(entry)
        tracecode.resolve_descriptors(e, True)
        er = tracecode.resolve_paths(e, cwd)
        assert "/TEST/dummytest.c" == er.args[0]
        assert "/extra/openssl-0.9.8y/test/rc5test.c" == er.args[1]

    def test_resolve_linkat_with_descriptors(self):
        cwd = "/TEST/"
        entry = """1412060538.783887 linkat(6</extra/dist>, "host/include/rbl/hal.h", 6</extra/dist2>, "st40/include/rbl/hal.h", 0) = 0"""
        e = tracecode.parse_entry(entry)
        tracecode.resolve_descriptors(e, True)
        er = tracecode.resolve_paths(e, cwd)
        assert "/extra/dist/host/include/rbl/hal.h" == er.args[0]
        assert "/extra/dist2/st40/include/rbl/hal.h" == er.args[1]

    def test_resolve_linkat_with_AT_FDCWD(self):
        cwd = "/TEST/"
        entry = """1412060538.783887 linkat(AT_FDCWD, "host/include/rbl/hal.h", AT_FDCWD, "st40/include/rbl/hal.h", 0) = 0"""
        e = tracecode.parse_entry(entry)
        tracecode.resolve_descriptors(e, True)
        er = tracecode.resolve_paths(e, cwd)
        assert "/TEST/host/include/rbl/hal.h" == er.args[0]
        assert "/TEST/st40/include/rbl/hal.h" == er.args[1]

    def test_resolve_linkat_with_mixed_FD_and_AT_FDCWD(self):
        cwd = "/TEST/"
        entry = """1412060538.783887 linkat(6</extra/dist>, "host/include/rbl/hal.h", AT_FDCWD, "st40/include/rbl/hal.h", 0) = 0"""
        e = tracecode.parse_entry(entry)
        tracecode.resolve_descriptors(e, True)
        er = tracecode.resolve_paths(e, cwd)
        assert "/extra/dist/host/include/rbl/hal.h" == er.args[0]
        assert "/TEST/st40/include/rbl/hal.h" == er.args[1]

    def test_resolve_renameat_with_mixed_FD_and_AT_FDCWD(self):
        cwd = "/TEST/"
        entry = """1412060538.783887 renameat(6</extra/dist>, "host/include/rbl/hal.h", AT_FDCWD, "st40/include/rbl/hal.h", 0) = 0"""
        e = tracecode.parse_entry(entry)
        tracecode.resolve_descriptors(e, True)
        er = tracecode.resolve_paths(e, cwd)
        assert "/extra/dist/host/include/rbl/hal.h" == er.args[0]
        assert "/TEST/st40/include/rbl/hal.h" == er.args[1]

    def test_parse_line_new_process_vfork(self):
        MockProcess = collections.namedtuple("Process", "ppid pid cwd children")
        cwd = "/"
        proc = MockProcess(None, 1, cwd, {})
        line = """1389171522.570319 vfork() = 2453412"""
        stgs = conf.DefaultSettings()
        kid = tracecode.parse_line(line, proc, settings=stgs)
        assert 1 == kid.ppid
        assert "1389171522.570319" == kid.tstamp
        assert 2453412 == kid.pid
        assert cwd == kid.cwd
        assert 1 == len(proc.children)

    def test_parse_line_new_process_clone(self):
        MockProcess = collections.namedtuple("Process", "ppid pid cwd children execs")
        cwd = "/"
        ex = tracecode.Exec(command="bin/ls", args=[], tstamp="0.1")
        proc = MockProcess(
            None, 1, cwd, {}, [tracecode.Exec(command="bin/bash", args=[], tstamp="0.1"), ex]
        )
        line = """1389171522.570319 clone() = 2453412"""
        stgs = conf.DefaultSettings()
        kid = tracecode.parse_line(line, proc, settings=stgs)
        assert 1 == kid.ppid
        assert "1389171522.570319" == kid.tstamp
        assert 2453412 == kid.pid
        assert cwd == kid.cwd
        assert 1 == len(proc.children)
        assert [ex] == kid.execs

    def test_resolve_descriptors_read1(self):
        entry = """1389171522.388349 read(4</home/nexb/tools/strace/strace-4.8/Makefile>, "", 4096) = 0"""
        e = tracecode.parse_entry(entry)
        tracecode.resolve_descriptors(e)
        assert "/home/nexb/tools/strace/strace-4.8/Makefile" == e.args[0]

    def test_resolve_descriptors_write1(self):
        entry = """1389171522.392467 write(1</dev/pts/6>, "/bin/mkdir -p ./linux\n", 22) = 22"""
        e = tracecode.parse_entry(entry)
        tracecode.resolve_descriptors(e)
        assert "/dev/pts/6" == e.args[0]

    def test_resolve_descriptors_fchdir(self):
        entry = """1389268368.859844 fchdir(7</home/nexb/build/jb4.3-14.10.0Q3.X-79/frameworks/base/media/tests/MediaDump/res>) = 0"""
        e = tracecode.parse_entry(entry)
        tracecode.resolve_descriptors(e)
        assert (
            "/home/nexb/build/jb4.3-14.10.0Q3.X-79/frameworks/base/media/tests/MediaDump/res"
            == e.args[0]
        )

    def test_resolve_descriptor_logs_warning_for_non_decodable_desc(self):
        entry = (
            """1389171522.388349 dup2(12</home/nexb/tools/strace/strace-4.8/Makefile>, 255) = 0"""
        )
        e = tracecode.parse_entry(entry)
        err = tracecode.resolve_descriptors(e, True)
        assert True == err
        assert "/home/nexb/tools/strace/strace-4.8/Makefile" == e.args[0]
        assert "255" == e.args[1]

    def test_resolve_paths_chdir(self):
        cwd = "/TEST/"
        entry = (
            '1389098994.521748 rename("./net/core/.filter.o.tmp", "/net/core/.filter.o.cmd") = 0'
        )
        e = tracecode.parse_entry(entry)
        er = tracecode.resolve_paths(e, cwd)
        assert "/TEST/net/core/.filter.o.tmp" == er.args[0]
        assert "/net/core/.filter.o.cmd" == er.args[1]

    def test_parse_line_change_dir_fchdir(self):
        proc = tracecode.Process(ppid=None, pid=1, cwd="/")
        line = """1389268368.859844 fchdir(7</home/nexb/build/jb4.3-14.10.0Q3.X-79>) = 0"""
        stgs = conf.DefaultSettings()
        tracecode.parse_line(line, proc, settings=stgs)
        assert "/home/nexb/build/jb4.3-14.10.0Q3.X-79" == proc.cwd

    def test_parse_line_change_dir_getcwd(self):
        proc = tracecode.Process(ppid=None, pid=1, cwd="/")
        line = """1389098278.877734 getcwd("/home/nexb/build/jb4.3-14.10.0Q3.X-80", 4096) = 38"""
        stgs = conf.DefaultSettings()
        tracecode.parse_line(line, proc, settings=stgs)
        assert "/home/nexb/build/jb4.3-14.10.0Q3.X-80" == proc.cwd

    def test_parse_line_change_dir_multiple_times(self):
        proc = tracecode.Process(ppid=None, pid=1, cwd="/")
        assert "/" == proc.cwd
        line = """1389268368.859844 fchdir(7</home/nexb/build/jb4.3-14.10.0Q3.X-79>) = 0"""
        stgs = conf.DefaultSettings()
        tracecode.parse_line(line, proc, settings=stgs)
        assert "/home/nexb/build/jb4.3-14.10.0Q3.X-79" == proc.cwd

        line = """1389098278.877734 getcwd("/home/nexb/build/jb4.3-14.10.0Q3.X-80", 4096) = 38"""
        tracecode.parse_line(line, proc, settings=stgs)
        assert "/home/nexb/build/jb4.3-14.10.0Q3.X-80" == proc.cwd

        line = """1389098278.877734 chdir("/home", 4096) = 38"""
        tracecode.parse_line(line, proc, settings=stgs)
        assert "/home" == proc.cwd

    def test_parse_line_exec(self):
        proc = tracecode.Process(ppid=None, pid=1, cwd=None)
        line = """1389171528.448801 execve("/bin/bash", ["/bin/bash", "-c", "gcc -Wall -Wwrite-strings -g -O2   -o strace bjm.o ."...], [/* 24 vars */]) = 0"""
        stgs = conf.DefaultSettings()
        tracecode.parse_line(line, proc, settings=stgs)
        assert 1 == len(proc.execs)
        assert "/bin/bash" == proc.execs[0].command
        expected = ["/bin/bash", "-c", "gcc -Wall -Wwrite-strings -g -O2   -o strace bjm.o ...."]
        assert expected == proc.execs[0].args

    def test_parse_line_exec_multiple(self):
        cwd = "/a/b/c/d/e/f/g/h/i/"
        proc = tracecode.Process(ppid=None, pid=1, cwd=cwd)
        line = """1389270100.658422 execve("/bin/sh", ["/bin/sh", "-c", "(cat /dev/null; ) > sound/pci/nm"...], [/* 147 vars */]) = 0"""
        stgs = conf.DefaultSettings()
        tracecode.parse_line(line, proc, settings=stgs)
        assert 1 == len(proc.execs)
        assert "/bin/sh" == proc.execs[0].command
        assert ["/bin/sh", "-c", "(cat /dev/null; ) > sound/pci/nm..."] == proc.execs[0].args

        line = """1389270180.377798 execve("../../../../../../kernel/scripts/gcc-wrapper.py", ["../../../../../../kernel/scripts"..., "arm-eabi-gcc", "/home/nexb/build/jb4.3-14.10.0Q3"..., "-I../../../../../../kernel/arch/"..., "-Inet/core", "-D__KERNEL__", "-mlittle-endian", ...], [/* 147 vars */]) = 0"""
        tracecode.parse_line(line, proc, settings=stgs)
        assert 2 == len(proc.execs)
        assert "/bin/sh" == proc.execs[0].command
        assert ["/bin/sh", "-c", "(cat /dev/null; ) > sound/pci/nm..."] == proc.execs[0].args
        assert "/a/b/c/kernel/scripts/gcc-wrapper.py" == proc.execs[1].command
        expected = [
            "../../../../../../kernel/scripts...",
            "arm-eabi-gcc",
            "/home/nexb/build/jb4.3-14.10.0Q3...",
            "-I../../../../../../kernel/arch/...",
            "-Inet/core",
            "-D__KERNEL__",
            "-mlittle-endian",
            "...",
        ]
        assert expected == proc.execs[1].args

    def test_parse_line_read(self):
        proc = tracecode.Process(ppid=None, pid=1, cwd=None)
        line = """1389171522.377832 read(4</home/nexb/tools/strace/strace-4.8/Makefile>, "# Makefile.in generated by automake 1.11.6 \n\n# Copyright (C) 1994 Free Software\n#"..., 4096) = 4096"""
        stgs = conf.DefaultSettings()
        tracecode.parse_line(line, proc, settings=stgs)
        assert 1 == len(proc.reads)
        assert "/home/nexb/tools/strace/strace-4.8/Makefile" in proc.reads

    def test_parse_line_pread(self):
        proc = tracecode.Process(ppid=None, pid=1, cwd=None)
        line = """1389171522.377832 pread(4</home/nexb/tools/strace/strace-4.8/Makefile>, "# Makefile.in generated by automake 1.11.6 \n\n# Copyright (C) 1994 Free Software\n#"..., 4096) = 4096"""
        stgs = conf.DefaultSettings()
        tracecode.parse_line(line, proc, settings=stgs)
        assert 1 == len(proc.reads)
        assert "/home/nexb/tools/strace/strace-4.8/Makefile" in proc.reads

    def test_parse_line_write(self):
        proc = tracecode.Process(ppid=None, pid=1, cwd=None)
        line = """1389171522.392467 write(1</dev/pts/6>, "/bin/mkdir -p ./linux\n", 22) = 22"""
        stgs = conf.DefaultSettings()
        tracecode.parse_line(line, proc, settings=stgs)
        assert 0 == len(proc.writes)

    def test_parse_line_write2(self):
        proc = tracecode.Process(ppid=None, pid=1, cwd=None)
        line = """1389171522.392467 write(1</my/path/6>, "/bin/mkdir -p ./linux\n", 22) = 22"""
        stgs = conf.DefaultSettings()
        tracecode.parse_line(line, proc, settings=stgs)
        assert 1 == len(proc.writes)
        assert "/my/path/6" in proc.writes

    def test_parse_line_rename(self):
        proc = tracecode.Process(ppid=None, pid=1, cwd=None)
        line = """1389099130.880026 rename("net/netfilter/.tmp_xt_string.o", "net/netfilter/xt_string.o") = 0"""
        stgs = conf.DefaultSettings()
        tracecode.parse_line(line, proc, settings=stgs)
        assert 1 == len(proc.readwrites)
        assert "net/netfilter/.tmp_xt_string.o" == proc.readwrites[0].source
        assert "net/netfilter/xt_string.o" == proc.readwrites[0].target

    def test_parse_line_rename_with_cwd(self):
        proc = tracecode.Process(ppid=None, pid=1, cwd="/base/")
        line = """1389099130.880026 rename("net/netfilter/.tmp_xt_string.o", "net/netfilter/xt_string.o") = 0"""
        stgs = conf.DefaultSettings()
        tracecode.parse_line(line, proc, settings=stgs)
        assert 1 == len(proc.readwrites)
        assert "/base/net/netfilter/.tmp_xt_string.o" == proc.readwrites[0].source
        assert "/base/net/netfilter/xt_string.o" == proc.readwrites[0].target

    def test_is_ignored_path(self):
        assert not tracecode.is_ignored_path("/dev/pts/5", None)
        assert tracecode.is_ignored_path("/dev/pts/5", conf.SYS_CONFIG)
        assert tracecode.is_ignored_path("/usr/lib/libssl.so.1", conf.DEFAULT_IGNORED_READS)
        assert not tracecode.is_ignored_path("/usr/lib/libssl.a", conf.DEFAULT_IGNORED_READS)

    def test_process_simple_command1(self):
        cwd = "/home/nexb"
        input_dir = self.get_tst_path("grep/trace")
        output_dir = None
        done = tracecode.parse_raw_traces(
            cwd, input_dir, output_dir, parallel=False, settings=conf.DefaultSettings(), clean=False
        )
        reads = {
            "/home/nexb/tools/patchelf/patchelf-0.5/tests/simple.c": "1389356960.219866",
            "/home/nexb/tools/patchelf/patchelf-0.5/README": "1389356960.191213",
            "/home/nexb/tools/patchelf/patchelf-0.5/tests/main.c": "1389356960.220131",
            "/home/nexb/tools/patchelf/patchelf-0.5/configure.ac": "1389356960.191502",
            "/home/nexb/tools/patchelf/patchelf-0.5/depcomp": "1389356960.210019",
            "/home/nexb/tools/patchelf/patchelf-0.5/COPYING": "1389356960.211372",
            "/home/nexb/tools/patchelf/patchelf-0.5/src/patchelf": "1389356960.208272",
            "/home/nexb/tools/patchelf/patchelf-0.5/install-sh": "1389356960.210781",
            "/home/nexb/tools/patchelf/patchelf-0.5/Makefile.in": "1389356960.191767",
            "/home/nexb/tools/patchelf/patchelf-0.5/src/elf.h": "1389356960.208641",
        }

        proc = done[0]
        assert reads == proc.reads

        writes = {"/home/license": "1389356960.211761"}
        assert writes == proc.writes

    def test_process_simple_command2(self):
        cwd = "/home/nexb"
        input_dir = self.get_tst_path("grep2/trace")
        output_dir = None
        done = tracecode.parse_raw_traces(
            cwd, input_dir, output_dir, parallel=False, settings=conf.DefaultSettings(), clean=False
        )
        reads = {
            "/home/nexb/tools/patchelf/patchelf-0.5/tests/main.c": "1389356960.220131",
            "/home/nexb/tools/patchelf/patchelf-0.5/tests/simple.c": "1389356960.219866",
            "/home/nexb/tools/patchelf/patchelf-0.5/README": "1389356960.191213",
        }

        proc = sorted(done, key=lambda x: x.pid)[0]
        assert 2799712 == proc.pid
        assert reads == proc.reads

        writes = {"/home/license": "1389356960.211761"}
        assert writes == proc.writes

        readwrites = [
            ("/home/nexb/tests/simple.c", "/tmp/tests/simple.c"),
            ("/tmp/tests/simple.c", "/home/nexb/tests/simple.c"),
        ]
        preadwrites = [
            (
                r.source,
                r.target,
            )
            for r in proc.readwrites
        ]
        assert readwrites == preadwrites

        assert {2799713: "1389356960.220049"} == proc.children

    def test_parse_entry_pipes_should_not_be_ignored1(self):
        e = tracecode.parse_entry('1389366380.196699 read(3<pipe:[15206912]>, "all\n", 128) = 4')
        assert "3<pipe:[15206912]>" == e.args[0]

    def test_parse_entry_pipes_should_not_be_ignored2(self):
        e = tracecode.parse_entry('1389366380.204714 read(0<pipe:[15213549]>, "", 4096) = 0')
        assert "0<pipe:[15213549]>" == e.args[0]

    def test_parse_entry_pipes_should_not_be_ignored3(self):
        e = tracecode.parse_entry('1389366380.204850 write(1<pipe:[15206912]>, "all\n", 4) = 4')
        assert "1<pipe:[15206912]>" == e.args[0]

    def test_parse_entry_sockets_should_not_be_ignored1(self):
        e = tracecode.parse_entry('1389366380.196699 read(3<socket:[15206912]>, "all\n", 128) = 4')
        assert "3<socket:[15206912]>" == e.args[0]

    def test_parse_entry_sockets_should_not_be_ignored2(self):
        e = tracecode.parse_entry('1389366380.204714 read(0<socket:[15213549]>, "", 4096) = 0')
        assert "0<socket:[15213549]>" == e.args[0]

    def test_parse_entry_sockets_should_not_be_ignored3(self):
        e = tracecode.parse_entry('1389366380.204850 write(1<socket:[15206912]>, "all\n", 4) = 4')
        assert "1<socket:[15206912]>" == e.args[0]

    def test_Process_object_can_be_pickled(self):
        proc = tracecode.Process(pid=1, ppid=0, cwd="/", init_exec="bash", tstamp="0.1")
        proc.children = {12: 13}
        proc.execs = [22, 23]
        proc.reads = ["a", "b"]
        proc.writes = ["c", "d"]
        proc.readwrites = ["e", "f"]
        import pickle

        pd = pickle.dumps(proc)
        pl = pickle.loads(pd)
        assert proc.children == pl.children

    def test_command_line_parse_simple(self):
        input_dir = self.extract_trace("patchelf_command")
        cwd = "/home/nexb/tools/strace/strace-4.8"
        output_dir = self.get_temp_dir()
        args = ["-q", f"--cwd={cwd}", "parse", input_dir, output_dir]
        self.run_tracecode_command(args)
        files = sorted(os.listdir(output_dir))
        assert 18 == len(files)

    def test_command_line_parse_with_ignored_reads(self):
        input_dir = self.extract_trace("patchelf_command2")
        cwd = "/home/nexb/tools/strace/strace-4.8"
        output_dir = self.get_temp_dir()
        args = [
            "-q",
            f"--cwd={cwd}",
            '--ignored_reads="/blabbla/*"',
            "parse",
            input_dir,
            output_dir,
        ]
        self.run_tracecode_command(args)
        procs = tracecode.load_from_dir(output_dir)
        ar = self.get_tst_path(join("patchelf_command2", "expected_pformats.tar.bz2"))
        expected_pf = join(self.extract_archive(ar), "expected_pformats")
        regen = False
        for proc in procs:
            fn = join(expected_pf, str(proc.pid))
            if regen or _GLOBAL_REGEN:
                with open(fn, "w") as o:
                    o.write(proc.pformat())
            with open(fn) as fin:
                expected = fin.read().splitlines()
                assert expected == proc.pformat().splitlines()
        if regen or _GLOBAL_REGEN:
            tar_dir = "expected_pformats"
            self.build_archive(expected_pf, tar_dir, ar)

    def test_command_line_parse_with_ignored_reads_from_file(self):
        # same as test_command_line_parse_with_single_read_ignore
        # but with two reads ignored
        input_dir = self.extract_trace("patchelf_command2")
        cwd = "/home/nexb/tools/strace/strace-4.8"
        output_dir = self.get_temp_dir()
        irf = self.get_tst_path("patchelf_command2/ignored_reads.lst")
        args = [
            "-q",
            f"--cwd={cwd}",
            "--ignored_reads_from=%s" % irf,
            '--ignored_reads="/bar/*"',
            "parse",
            input_dir,
            output_dir,
        ]
        self.run_tracecode_command(args)
        procs = tracecode.load_from_dir(output_dir)
        ar = self.get_tst_path(join("patchelf_command2", "expected_pformats.tar.bz2"))
        extracted = self.extract_archive(ar)
        expected_pf = join(extracted, "expected_pformats")

        regen = False
        for proc in procs:
            fn = join(expected_pf, str(proc.pid))
            if regen or _GLOBAL_REGEN:
                with open(fn, "w") as o:
                    o.write(proc.pformat())
            with open(fn) as fin:
                expected = fin.read().splitlines()
                assert expected == proc.pformat().splitlines()
        if regen or _GLOBAL_REGEN:
            tar_dir = "expected_pformats"
            self.build_archive(expected_pf, tar_dir, ar)

    def test_patterns_from_file(self):
        irf = self.get_tst_path("patchelf_command2/ignored_reads.lst")
        pff = conf.patterns_from_file(irf)
        assert ("/foo/*", "-/foobar/*", "/bar/*") == pff

    def test_parse_line_ignore_errors(self):
        trace_file = self.get_tst_path("bug1/t.2461545")
        proc = tracecode.Process(1, 0, None)
        stgs = conf.DefaultSettings()
        with open(trace_file) as fin:
            for line in fin:
                result = tracecode.parse_line(line, proc, settings=stgs)
                assert None == result

    def test_is_multiplexed(self):
        trace_file = self.get_tst_path("interleaving/trace/cp-trace.1")
        done = Queue()
        proc = tracecode.Process(
            pid=1,
            ppid=0,
            cwd="/",
        )
        tracecode.parse_trace_file(proc, trace_file, None, done, output_dir=None)
        stgs = conf.BaseSettings()
        muxers = stgs.multiplexers
        assert proc.is_multiplexed(muxers)

    def test_demux(self):
        trace_file = self.get_tst_path("interleaving/trace/cp-trace.2")
        done = Queue()
        proc = tracecode.Process(
            pid=1,
            ppid=0,
            cwd="/",
        )
        bare_settings = conf.DefaultSettings()
        bare_settings.multiplexers = []
        tracecode.parse_trace_file(
            proc, trace_file, None, done, output_dir=None, settings=bare_settings
        )
        stgs = conf.BaseSettings()
        muxers = stgs.multiplexers
        assert proc.is_multiplexed(muxers)
        bef = """Process: pid=1, ppid=0, execs='/bin/cp', tstamp=0:
 Reads:
  /home/nexb/tmp/c
  /home/nexb/tmp/d
 Writes:
  /home/nexb/tmp/dir/c
  /home/nexb/tmp/dir/d
 Read/Writes:
 Children:"""
        before = proc.pformat()
        assert bef == before

        proc.demux(muxers)  # @UndefinedVariable
        af = """Process: pid=1, ppid=0, execs='/bin/cp', tstamp=0:
 Reads:
 Writes:
 Read/Writes:
  ('/home/nexb/tmp/c', '/home/nexb/tmp/dir/c')
  ('/home/nexb/tmp/d', '/home/nexb/tmp/dir/d')
 Children:"""
        after = proc.pformat()
        assert af == after

    def test_demux_single_readwrite(self):
        proc = tracecode.Process(pid=1, ppid=0, cwd="/", init_exec=tracecode.Exec("/bin/cp", "", 0))
        muxers = ["*/cp"]
        assert proc.is_multiplexed(muxers)
        proc.add_read("/read/path", "0", [])
        proc.add_write("/write/path2", "0", [])
        proc.demux(muxers)
        assert {} != proc.reads
        assert {} != proc.writes
        assert proc.readwrites == []

    def test_demux_cp(self):
        trace_file = self.get_tst_path("interleaving/trace/t.15480")
        done = Queue()
        proc = tracecode.Process(pid=1, ppid=0, cwd=None)
        settings = conf.BaseSettings()
        # fake no demuxing first
        muxers = settings.multiplexers[:]
        settings.multiplexers = []
        tracecode.parse_trace_file(proc, trace_file, None, done, output_dir=None, settings=settings)

        settings.multiplexers = muxers
        assert proc.is_multiplexed(muxers)
        proc.demux(muxers)
        af = """Process: pid=1, ppid=0, execs='/bin/cp', tstamp=0:
 Reads:
  /lib64/libselinux.so.1
  /lib64/librt-2.12.so
  /lib64/libacl.so.1.1.0
  /lib64/libattr.so.1.1.0
  /lib64/libc-2.12.so
  /lib64/libdl-2.12.so
  /lib64/libpthread-2.12.so
  /proc/filesystems
 Writes:
 Read/Writes:
  ('/home/nexb/build/tools/systemsupport/alarm.sh', '/home/nexb/bin/alarm.sh')
  ('/home/nexb/build/tools/systemsupport/config.sh', '/home/nexb/bin/config.sh')
  ('/home/nexb/build/tools/systemsupport/events.sh', '/home/nexb/bin/events.sh')
  ('/home/nexb/build/tools/systemsupport/hardware.sh', '/home/nexb/bin/hardware.sh')
  ('/home/nexb/build/tools/systemsupport/logreport.sh', '/home/nexb/bin/logreport.sh')
  ('/home/nexb/build/tools/systemsupport/mainreport.sh', '/home/nexb/bin/mainreport.sh')
  ('/home/nexb/build/tools/systemsupport/resource.sh', '/home/nexb/bin/resource.sh')
  ('/home/nexb/build/tools/systemsupport/software.sh', '/home/nexb/bin/software.sh')
  ('/home/nexb/build/tools/systemsupport/systemsupport', '/home/nexb/bin/systemsupport')
 Children:""".splitlines()
        after = proc.pformat().splitlines()
        assert after == af

    def test_demux_cp_with_file_with_same_name(self):
        trace_file = self.get_tst_path("interleaving/trace/same_name.15480")
        done = Queue()
        proc = tracecode.Process(pid=1, ppid=0, cwd=None)
        settings = conf.BaseSettings()
        # fake no demuxing first
        muxers = settings.multiplexers[:]
        settings.multiplexers = []
        tracecode.parse_trace_file(proc, trace_file, None, done, output_dir=None, settings=settings)

        # print(proc.pformat())
        assert proc.is_multiplexed(muxers)
        proc.demux(muxers)
        expected = """Process: pid=1, ppid=0, execs='/bin/cp', tstamp=0:
 Reads:
 Writes:
 Read/Writes:
  ('/home/nexb/build/tools/systemsupport/hardware.sh', '/home/nexb/bin/systemsupport/hardware.sh')
  ('/home/nexb/build/tools/systemsupport2/hardware.sh', '/home/nexb/bin/systemsupport2/hardware.sh')
 Children:""".splitlines()
        after = proc.pformat().splitlines()
        assert after == expected

    def test_filter_ignored(self):
        proc = tracecode.Process(
            pid=1, ppid=0, cwd="/", init_exec=tracecode.Exec("/bin/bash", "", 0)
        )
        proc.add_read("/read/path", "0", [])
        proc.add_write("/write/path2", "0", [])
        proc.add_write("/write/path", "0", [])
        proc.add_readwrite("/read/read", "/write/read", "0", "0", [], [])
        proc.add_readwrite("/my/path", "/your/path", "0", "0", [], [])
        assert {} != proc.reads
        assert {} != proc.writes
        assert [] != proc.readwrites

        proc.filter(
            ignored_reads=("*/path",),
            ignored_writes=(
                "*/path*",
                "-*/path2",
            ),
            ignored_execs=[],
        )
        assert sorted(proc.reads_paths()) == ["/read/read"]
        assert sorted(proc.writes_paths()) == ["/write/path2", "/write/read"]

    def test_filter_ignored_pipes_and_sockets(self):
        proc = tracecode.Process(
            pid=1, ppid=0, cwd="/", init_exec=tracecode.Exec("/bin/bash", "", 0)
        )
        proc.add_read("pipe:[1234]", "0", [])
        proc.add_read("socket:[14234]", "0", [])
        proc.add_write("pipe:[456343]", "0", [])
        proc.add_write("socket:[456343]", "0", [])
        proc.add_write("pipe:[45633]", "0", [])
        proc.add_readwrite("pipe:[4561233]", "socket:[4561233]", "0", "0", [], [])
        proc.add_readwrite("socket:[4561233]", "socket:[4561233]", "0", "0", [], [])
        assert {} != proc.reads
        assert {} != proc.writes
        assert [] != proc.readwrites
        proc.filter(
            ignored_reads=(
                "pipe:*",
                "socket:*",
            ),
            ignored_writes=(
                "pipe:*",
                "socket:*",
            ),
            ignored_execs=[],
        )
        assert proc.reads_paths() == set([])
        assert proc.writes_paths() == set([])

    def test_filter_ignored_execs(self):
        proc = tracecode.Process(
            pid=1, ppid=0, cwd="/", init_exec=tracecode.Exec("/bin/bash", "", 0)
        )
        proc.add_read("/read/path", "0", [])
        proc.add_write("/write/path2", "0", [])
        proc.add_write("/write/path", "0", [])
        proc.add_readwrite("/read/read", "/write/read", "0", "0", [], [])
        proc.add_readwrite("/my/path", "/your/path", "0", "0", [], [])
        proc.filter(ignored_reads=[], ignored_writes=[], ignored_execs=["/bin/bash"])
        assert proc.reads == {}
        assert proc.writes == {}
        assert proc.readwrites == []
        expected = tracecode.Exec("/bin/bash", "", 0)
        assert proc.execs == [expected]

    def test_as_ops(self):
        cwd = "/home/nexb"
        input_dir = self.get_tst_path("as_ops/trace")
        output_dir = None
        done = tracecode.parse_raw_traces(
            cwd, input_dir, output_dir, parallel=False, settings=conf.DefaultSettings(), clean=False
        )
        expected = [
            tracecode.Operation(
                pid=2799712,
                command="/bin/grep",
                sources=sorted(
                    [
                        "/home/nexb/tools/patchelf/patchelf-0.5/tests/simple.c",
                        "/home/nexb/tools/patchelf/patchelf-0.5/README",
                        "/home/nexb/tools/patchelf/patchelf-0.5/tests/main.c",
                        "/home/nexb/tools/patchelf/patchelf-0.5/configure.ac",
                        "/home/nexb/tools/patchelf/patchelf-0.5/depcomp",
                        "/home/nexb/tools/patchelf/patchelf-0.5/COPYING",
                        "/home/nexb/tools/patchelf/patchelf-0.5/src/patchelf",
                        "/home/nexb/tools/patchelf/patchelf-0.5/install-sh",
                        "/home/nexb/tools/patchelf/patchelf-0.5/Makefile.in",
                        "/home/nexb/tools/patchelf/patchelf-0.5/src/elf.h",
                    ]
                ),
                targets=[
                    "/home/license",
                ],
                start_tstamp="1389356960.191213",
                end_tstamp="1389356960.220131",
            ).to_dict()
        ]
        proc = done[0]
        ao = [o.to_dict() for o in proc.as_ops()]
        ao[0]["sources"].sort()
        assert ao == expected

    def test_as_ops_handles_multiplexing_correctly(self):
        input_dir = self.extract_trace("as_ops_multiplexed")
        procs = tracecode.parse_raw_traces(
            None,
            input_dir,
            output_dir=None,
            parallel=False,
            settings=conf.BaseSettings(),
            clean=False,
        )

        ao = sorted([repr(o) for o in procs[0].as_ops()])
        ef = self.get_tst_path(join("as_ops_multiplexed", "expected"))
        regen = False
        if regen or _GLOBAL_REGEN:
            with open(ef, "w") as of:
                of.write("\n".join(ao))

        expected = sorted([f for f in open(ef).read().splitlines() if f])
        assert ao == expected

    def test_stats_no_stat(self):
        input_dir = self.extract_trace("stats_patchelf")
        output_dir = None
        procs = tracecode.parse_raw_traces(
            None, input_dir, output_dir, parallel=True, settings=conf.BaseSettings()
        )
        expected = """Parsing statistics
==================
Counters
--------
Ignored failed calls: 0
Line parsing errors: 0
Descriptor warnings: 0

Number of calls per syscall
---------------------------

Unhandled syscalls
------------------"""
        result = tracecode.parsing_statistics(procs)
        assert result == expected

    def test_stats_stat(self):
        input_dir = self.extract_trace("stats_patchelf")
        output_dir = None
        settings = conf.BaseSettings()
        settings.stats = True
        procs = tracecode.parse_raw_traces(
            None, input_dir, output_dir, parallel=True, settings=settings
        )
        expected = """Parsing statistics
==================
Counters
--------
Ignored failed calls: 736
Line parsing errors: 0
Descriptor warnings: 0

Number of calls per syscall
---------------------------
write: 1302
read: 974
open: 366
openat: 23
execve: 18
arch_prctl: 18
vfork: 9
clone: 8
chdir: 6
getcwd: 4
rename: 1

Unhandled syscalls
------------------
arch_prctl
"""
        result = tracecode.parsing_statistics(procs)
        assert expected.splitlines() == result.splitlines()

    def test_incomplete_trace_parsing_does_not_hangs_but_timesout(self):

        def timeoutfunc(x):
            # short timeout
            return 1

        try:
            # NOTE the trace has been doctored such that PID 2800302
            # is a trace file without any reference in the stack of PIDs
            input_dir = self.extract_trace("parse_does_not_hang")
            tracecode.parse_raw_traces(None, input_dir, timeout_func=timeoutfunc)
        except Queue_Empty:
            # success
            pass

    def test_incomplete_trace_parsing_does_not_hangs_but_timesout_todir(self):

        def timeoutfunc(x):
            # short timeout
            return 1

        output_dir = self.get_temp_dir()
        try:
            # short timeout
            tracecode.TIMEOUT = 1
            # NOTE the trace has been doctored such that PID 2800302
            # is a trace file without any reference in the stack of PIDs
            input_dir = self.extract_trace("parse_does_not_hang")
            tracecode.parse_raw_traces(None, input_dir, output_dir, timeout_func=timeoutfunc)
        except Queue_Empty:
            # success
            pass

    def test_parse_line_without_error(self):
        bd = self.get_tst_path("parse_error")
        proc = tracecode.Process(0, 1, None)
        with open(join(bd, "trace.1")) as trace:
            for line in trace:
                tracecode.parse_line(line, proc, settings=conf.BaseSettings())

    def test_main_parse_with_filter_does_apply_defaults(self):
        raw_dir = self.get_tst_path("filtering/t")

        parsed_dir = self.get_temp_dir()
        args = {"parse": True, "TRACE_DIR": raw_dir, "PARSED_DIR": parsed_dir}
        tracecode.main(args)
        proc = tracecode.Process.load(parsed_dir, 70676)
        assert 3 == len([p for p in proc.reads if p.startswith("/lib/i386-linux-gnu/")])

        parsed_dir2 = self.get_temp_dir()
        args = {
            "parse": True,
            "TRACE_DIR": raw_dir,
            "--ignored_reads": ["/lib*"],
            "PARSED_DIR": parsed_dir2,
        }
        tracecode.main(args)
        proc2 = tracecode.Process.load(parsed_dir2, 70676)
        assert 0 == len([p for p in proc2.reads if p.startswith("/lib/i386-linux-gnu/")])

        parsed_dir = self.get_temp_dir()
        args = {"parse": True, "TRACE_DIR": raw_dir, "PARSED_DIR": parsed_dir}
        tracecode.main(args)
        proc3 = tracecode.Process.load(parsed_dir, 70676)
        assert 3 == len([p for p in proc3.reads if p.startswith("/lib/i386-linux-gnu/")])


class PathMatchingTest(BaseTestCase):

    def check_match(self, paths1, paths2, expected):
        matches = list(tracecode.match_paths(paths1, paths2))
        assert sorted(expected) == sorted(matches)

    def test_match_paths(self):
        paths1 = ["a/b/c"]
        paths2 = ["d/b/c"]
        expected = [("a/b/c", "d/b/c")]
        self.check_match(paths1, paths2, expected)

    def test_match_paths_two_matches(self):
        paths1 = ["a/b/c"]
        paths2 = ["d/b/c", "c/b/c"]
        expected = [
            ("a/b/c", "d/b/c"),
            ("a/b/c", "c/b/c"),
        ]
        self.check_match(paths1, paths2, expected)

    def test_match_paths_best_match(self):
        paths1 = ["a/b/c"]
        paths2 = ["d/b/c", "c/e/c"]
        expected = [("a/b/c", "d/b/c")]
        self.check_match(paths1, paths2, expected)

    def test_match_paths_no_match(self):
        paths1 = ["a/b/c"]
        paths2 = ["d/b/z", "c/e/z"]
        expected = []
        self.check_match(paths1, paths2, expected)

    def test_match_paths_empty_args(self):
        paths1 = []
        paths2 = []
        expected = []
        self.check_match(paths1, paths2, expected)

    def test_match_paths_empty_args2(self):
        paths1 = []
        paths2 = ["a"]
        expected = []
        self.check_match(paths1, paths2, expected)

    def test_match_paths_empty_args3(self):
        paths1 = ["a"]
        paths2 = []
        expected = []
        self.check_match(paths1, paths2, expected)

    def test_match_paths_long(self):

        def get_list(path):
            f = self.get_tst_path("match_path_long/" + path)
            return sorted(open(f).read().splitlines())

        paths1 = get_list("paths1.lst")
        paths2 = get_list("paths2.lst")
        expected = get_list("expected.lst")
        expected = [tuple(x.split(",")) for x in expected]

        regen = False
        if regen or _GLOBAL_REGEN:
            with open(self.get_tst_path("match_path_long/expected.lst"), "w") as o:
                for x, y in tracecode.match_paths(paths1, paths2):
                    o.write("%s,%s\n" % (x, y))
        self.check_match(paths1, paths2, expected)


class FilesetTest(BaseTestCase):

    def test_in_fileset_basic(self):
        assert tracecode.in_fileset("/nexb/src/", tuple())
        assert tracecode.in_fileset("/nexb/src/", None)
        assert not tracecode.in_fileset(None, None)

    def test_in_fileset(self):
        fileset = (
            "/nexb/src/*",
            "-/nexb/src/*.so",
        )
        assert not tracecode.in_fileset(None, fileset)
        assert not tracecode.in_fileset("", fileset)
        assert not tracecode.in_fileset("/", fileset)
        assert tracecode.in_fileset("/nexb/src/", fileset)
        assert not tracecode.in_fileset("/nexb/bin/", fileset)

    def test_in_fileset_exclusions(self):
        fileset = ("/nexb/src/*", "-/nexb/src/*.so")
        assert not tracecode.in_fileset("/nexb/src/dist/build/mylib.so", fileset)

    def test_in_fileset_weird_exclusions(self):
        fileset = ("/nexb/src/*", "-")
        assert tracecode.in_fileset("/nexb/src/", fileset)

    def test_in_fileset_sources(self):
        sources = (
            "/home/nexb/tools/patchelf/patchelf-0.5/*",
            "-/home/nexb/tools/patchelf/patchelf-0.5/src/patchelf",
            "-/home/nexb/tools/patchelf/patchelf-0.5/src/patchelf.o",
        )
        assert not tracecode.in_fileset(
            "/home/nexb/tools/patchelf/patchelf-0.5/src/patchelf", sources
        )

    def test_in_fileset_dot_svn(self):
        sources = ("*/.svn/*",)
        assert tracecode.in_fileset("home/nexb/tools/patchelf/.svn/", sources)
        assert tracecode.in_fileset("home/nexb/tools/.svn/this", sources)
        assert not tracecode.in_fileset("home/nexb/tools/this", sources)


class EndToEndTest(BaseTestCase):
    # These tests are end to end integration tests checking a full pformatted
    # output

    def test_process_simple_command_pformat(self):
        test_name = "pformat_grep2"
        cwd = "/home/nexb"
        self.check_pformats(test_name, cwd, with_output_dir=False, parallel=False, regen=False)

    def test_process_simple_command_pformat3(self):
        test_name = "pformat_grep3"
        cwd = "/home/nexb"
        self.check_pformats(test_name, cwd, with_output_dir=False, parallel=False, regen=False)

    def test_trace_complete_build_cups_with_multiprocessing(self):
        test_name = "pformat_cups"
        cwd = "/home/nexb/tools/cups/cups-1.4.6"
        self.check_pformats(test_name, cwd, with_output_dir=False, parallel=True, regen=False)

    def test_trace_complete_build_patchelf(self):
        cwd = "/home/nexb/tools/patchelf/patchelf-0.5"
        test_name = "pformat_patchelf"
        self.check_pformats(test_name, cwd, with_output_dir=False, parallel=False, regen=False)

    def test_trace_complete_build_strace_full(self):
        cwd = "/home/nexb/tools/strace/strace-4.8"
        test_name = "pformat_strace_full"
        self.check_pformats(test_name, cwd, with_output_dir=False, parallel=True, regen=False)

    def test_trace_complete_build_strace_saved_to_dir(self):
        cwd = "/home/nexb/tools/strace/strace-4.8"
        test_name = "pformat_strace_saved"
        self.check_pformats(test_name, cwd, with_output_dir=True, parallel=True, regen=False)

    def test_trace_cleaning_strace_full(self):
        cwd = "/home/nexb/tools/strace/strace-4.8"
        test_name = "pformat_strace_cleaning"
        self.check_pformats(
            test_name, cwd, with_output_dir=False, clean=True, parallel=True, regen=False
        )

    def test_trace_cleaning_strace_full_in_dir(self):
        cwd = "/home/nexb/tools/strace/strace-4.8"
        test_name = "pformat_strace_cleaning_dir"
        self.check_pformats(
            test_name, cwd, with_output_dir=True, clean=True, parallel=True, regen=False
        )

    @pytest.mark.skipif(not (on_linux and tracecode.has_dot()), reason="Run on Linux, with GCC and Graphviz to run this test")
    def test_trace_from_scratch_end_to_end(self):
        # test a live strace run and each read/write commands
        test_dir = self.get_temp_dir(delete=True)
        test_file = Path(test_dir) / "hello_world.c"
        with open(test_file, "w")  as o:
            o.write("""
#include <stdio.h>

int main(void)
{
    printf("Hello World!\\n");
}
""")

        trace_dir = self.get_temp_dir(delete=True)

        target_file = f"{test_dir}/hello_world"
        args = [
            "strace", "-ff", "-y", "-ttt", "-a1",
            "-o", f"{trace_dir}/trace",
            "gcc", f"{test_file}", "-o", target_file
        ]

        try:
            subprocess.check_output(args,
                cwd=test_dir,
                shell=False,
            )
        except subprocess.CalledProcessError as e:
            raise Exception(' '.join(args), e.output) from e

        assert os.path.exists(target_file)
        cwd = "/home/nexb/tools/strace/strace-4.8"
        output_dir = self.get_temp_dir()

        # tracecode [options] validate  TRACE_DIR
        self.run_tracecode_command([f"--cwd={cwd}", "validate", trace_dir])

        # tracecode [options] parse     TRACE_DIR   PARSED_DIR
        # tracecode parse /tmp/outputs /tmp/parsed_outputs
        parsed_dir = self.get_temp_dir()
        self.run_tracecode_command([f"--cwd={cwd}", "parse", trace_dir, parsed_dir])
        assert os.listdir(parsed_dir)

        # tracecode [options] filter    PARSED_DIR  [NEW_PARSED_DIR]
        parsed_dir2 = self.get_temp_dir()
        self.run_tracecode_command([f"--cwd={cwd}", "--defaults", "filter", parsed_dir, parsed_dir2])
        assert os.listdir(parsed_dir2)

        # tracecode list /tmp/parsed_outputs /tmp/a/reads /tmp/b/writes
        reads_file = os.path.join(output_dir, "reads.txt")
        writes_file = os.path.join(output_dir, "writes.txt")
        self.run_tracecode_command([f"--cwd={cwd}", "list", parsed_dir, reads_file, writes_file])
        assert os.path.exists(reads_file)
        assert os.path.exists(writes_file)

        # tracecode [options] guess     PARSED_DIR  SOURCES_FILE  TARGETS_FILE
        sources_file = os.path.join(output_dir, "sources.txt")
        targets_file = os.path.join(output_dir, "targets.txt")
        self.run_tracecode_command([f"--cwd={cwd}", "guess", parsed_dir, sources_file, targets_file])
        assert os.path.exists(sources_file)
        assert os.path.exists(targets_file)

        # tracecode [options] analyze PARSED_DIR  ANALYSIS_FILE
        analysis_file = os.path.join(output_dir, "analysis.csv")
        self.run_tracecode_command([
            f"--cwd={cwd}", "analyze",
            f"--sources_from={sources_file}",
            f"--targets={target_file}",
            parsed_dir, analysis_file
        ])
        assert os.path.exists(analysis_file)

        # tracecode [options] inventory PARSED_DIR  INV_FILE
        inventory_file = os.path.join(output_dir, "inventory.csv")
        self.run_tracecode_command([f"--cwd={cwd}", "inventory", parsed_dir, inventory_file])
        assert os.path.exists(inventory_file)

        # tracecode [options] graphic   PARSED_DIR  GRAPH_FILE
        graph_file = os.path.join(output_dir, "graph.txt")
        self.run_tracecode_command([f"--cwd={cwd}", "graphic", parsed_dir, graph_file])
        assert os.path.exists(f"{graph_file}.pdf")


class AltGraphTest(BaseTestCase):

    def test_altgraph_subgraph_bug(self):
        from tracecode._vendor.altgraph.Graph import Graph

        graph = Graph()
        graph.add_node("A")
        graph.add_node("B")
        graph.add_node("C")
        graph.add_edge("A", "B")
        graph.add_edge("B", "C")

        whole_graph = graph.forw_topo_sort()
        subgraph_backward = graph.back_bfs_subgraph("C")
        subgraph_backward = subgraph_backward.forw_topo_sort()
        assert whole_graph == subgraph_backward

        subgraph_forward = graph.forw_bfs_subgraph("A")
        subgraph_forward = subgraph_forward.forw_topo_sort()
        assert whole_graph == subgraph_forward

    def test_altgraph_nodes_connectivity(self):
        from tracecode._vendor.altgraph.Graph import Graph

        graph = Graph()
        graph.add_edge("A", "B")
        graph.add_edge("B", "C")
        graph.add_edge("C", "b")
        graph.add_edge("X", "Z")
        nl = graph.node_list()
        assert ["A", "B", "C", "X", "Z", "b"] == sorted(nl)

        A = set(graph.forw_bfs_subgraph("A").node_list())
        assert 4 == len(A)
        assert "Z" not in A
        assert "b" in A


class GraphicTest(BaseTestCase):
    # these tests are end to end integration tests checking for a graphviz dot
    # representation of a graph

    def check_render_graph_dot(self, test_name, procs, settings, regen=False):
        """
        Test function that generates a .dot output and checks against an
        expected output regen the expected if needed.
        """
        g = as_graph(procs, settings)
        out = join(self.get_temp_dir(), test_name + ".dot")
        expected = join(self.get_tst_path(test_name), "expected.dot")
        fn = tracecode.save_graphic(g, out, "dot")
        if regen or _GLOBAL_REGEN:
            shutil.copy(fn, expected)
        logger.debug("%(test_name)r graph dot saved to %(fn)s" % locals())
        assert open(expected).read().splitlines() == open(out).read().splitlines()

    @unittest.skipUnless(tracecode.has_dot(), "Install Graphviz to run tests")
    def test_render_graph_bare(self):
        cwd = "/home/nexb"
        input_dir = self.get_tst_path("render_graph/trace")
        stgs = conf.DefaultSettings()
        procs = tracecode.parse_raw_traces(
            cwd, input_dir, output_dir=None, parallel=False, settings=stgs, clean=False
        )
        self.check_render_graph_dot("render_graph", procs, settings=stgs)

    @unittest.skipUnless(tracecode.has_dot(), "Install Graphviz to run tests")
    def test_render_graph_patchelf_clean_parallel(self):
        cwd = "/home/nexb"
        input_dir = self.extract_trace("render_graph_patchelf")
        output_dir = None
        stgs = conf.DefaultSettings()
        procs = tracecode.parse_raw_traces(cwd, input_dir, output_dir, parallel=True, settings=stgs)
        self.check_render_graph_dot("render_graph_patchelf", procs, settings=stgs)

    @unittest.skipUnless(tracecode.has_dot(), "Install Graphviz to run tests")
    def test_render_graph_strace(self):
        cwd = "/home/nexb"
        input_dir = self.extract_trace("render_graph_strace")
        output_dir = None
        stgs = conf.DefaultSettings()
        procs = tracecode.parse_raw_traces(cwd, input_dir, output_dir, parallel=True, settings=stgs)
        self.check_render_graph_dot("render_graph_strace", procs, settings=stgs)

    @unittest.skipUnless(tracecode.has_dot(), "Install Graphviz to run tests")
    def test_render_graph_cups(self):
        cwd = "/home/nexb"
        input_dir = self.extract_trace("render_graph_cups")
        output_dir = None
        stgs = conf.DefaultSettings()
        procs = tracecode.parse_raw_traces(cwd, input_dir, output_dir, parallel=True, settings=stgs)
        self.check_render_graph_dot("render_graph_cups", procs, settings=stgs)

    @unittest.skipUnless(tracecode.has_dot(), "Install Graphviz to run tests")
    def check_render_graph_with_procs(self, test_name, cwd, settings, regen=False):
        input_dir = self.extract_trace(test_name)
        output_dir = self.get_temp_dir()
        procs = tracecode.parse_raw_traces(cwd, input_dir, None, parallel=True, settings=settings)
        out = join(self.get_temp_dir(), test_name + "expected.dot")
        tracecode.as_graphic_from_procs(procs, file_name=out, settings=settings, file_type="dot")
        expected = join(self.get_tst_path(test_name), "expected.dot")
        if regen or _GLOBAL_REGEN:
            shutil.copy(out, expected)
        logger.debug("%(test_name)r graph dot saved to %(out)s" % locals())
        assert open(out).read().splitlines() == open(expected).read().splitlines()

    @unittest.skipUnless(tracecode.has_dot(), "Install Graphviz to run tests")
    def test_procs_to_graphics_from_dir_patchelf(self):
        cwd = "/home/nexb"
        target = "/home/nexb/tools/patchelf/patchelf-0.5/src/patchelf"
        test_name = "render_graph_patchelf2"
        stgs = conf.DefaultSettings()
        stgs.ignored_writes += ("*build-log-*.log",)
        stgs.targets = [target]
        self.check_render_graph_with_procs(test_name, cwd, settings=stgs)

    @unittest.skipUnless(tracecode.has_dot(), "Install Graphviz to run tests")
    def test_procs_to_graphics_from_dir_bash(self):
        cwd = "/home/pombredanne/trace-code/test-projects/bash-4.1"
        target = "/home/pombredanne/trace-code/test-projects/bash-4.1/bash"
        test_name = "render_graph_bash"
        stgs = conf.DefaultSettings()

        stgs.ignored_writes += ("*build-log-*.log",)
        stgs.ignored_writes += conf.GCC_DEPEND_FILES

        stgs.ignored_reads += conf.GCC_DEPEND_FILES

        stgs.targets = [target]
        self.check_render_graph_with_procs(test_name, cwd, settings=stgs, regen=False)


class ListTest(BaseTestCase):

    def test_reads_writes_paths(self):
        cwd = "/home/nexb"
        input_dir = self.get_tst_path("lists/trace")
        output_dir = None

        rd = """/home/nexb/tools/patchelf/patchelf-0.5/configure.ac
                /home/nexb/tools/patchelf/patchelf-0.5/COPYING
                /home/nexb/tools/patchelf/patchelf-0.5/depcomp
                /home/nexb/tools/patchelf/patchelf-0.5/install-sh
                /home/nexb/tools/patchelf/patchelf-0.5/Makefile.in
                /home/nexb/tools/patchelf/patchelf-0.5/README
                /home/nexb/tools/patchelf/patchelf-0.5/src/elf.h
                /home/nexb/tools/patchelf/patchelf-0.5/src/patchelf
                /home/nexb/tools/patchelf/patchelf-0.5/tests/main.c
                /home/nexb/tools/patchelf/patchelf-0.5/tests/simple.c
                /lib/x86_64-linux-gnu/libdl-2.15.so
                /lib/x86_64-linux-gnu/libc-2.15.so
                """

        reads = sorted(set(rd.split()))

        stgs = conf.DefaultSettings()
        stgs.ignored_reads = tuple()
        stgs.ignored_writes = tuple()
        done = tracecode.parse_raw_traces(
            cwd, input_dir, output_dir, parallel=False, settings=stgs, clean=False
        )
        proc = done[0]
        assert sorted(proc.reads_paths()) == reads

        writes = sorted(["/home/license", "/dev/pts/11"])
        assert sorted(proc.writes_paths()) == writes

    def test_file_lists(self):
        cwd = "/home/nexb/tools/patchelf/patchelf-0.5"
        input_dir = self.extract_trace("lists_patchelf")
        output_dir = None
        stgs = conf.Settings(
            cwd=None, multiplexers=[], errors=[], ignored_reads=tuple(), ignored_writes=tuple()
        )

        procs = tracecode.parse_raw_traces(
            cwd, input_dir, output_dir, parallel=False, settings=stgs, clean=False
        )
        reads, writes = tracecode.file_lists(procs)

        expected_reads = open(self.get_tst_path("lists_patchelf/expected")).read().splitlines()
        assert sorted(expected_reads) == sorted(list(reads))

        expected_writes = """/dev/pts/11
            /dev/tty
            /home/nexb/tools/patchelf/patchelf-0.5/src/.deps/patchelf.Po
            /home/nexb/tools/patchelf/patchelf-0.5/src/.deps/patchelf.Tpo
            /home/nexb/tools/patchelf/patchelf-0.5/src/patchelf
            /home/nexb/tools/patchelf/patchelf-0.5/src/patchelf.o
            /tmp/ccDO5gyj.c
            /tmp/ccHpGGfn.o
            /tmp/ccSJnJSm.s
            /tmp/ccj50xXq.ld
            /tmp/ccxlsgGu.le""".split()
        assert sorted(expected_writes) == sorted(list(writes))

    def test_guess_sources_and_targets_patchelf_with_defaults_settings(self):
        cwd = "/home/nexb/tools/patchelf/patchelf-0.5"
        test_name = "analy_patchelf"

        input_dir = self.extract_trace(test_name)
        output_dir = None
        stgs = conf.DefaultSettings()
        procs = tracecode.parse_raw_traces(cwd, input_dir, output_dir, parallel=True, settings=stgs)
        sources, targets = tracecode.guess_sources_and_targets(procs)
        expected_srcs = """/home/nexb/tools/patchelf/patchelf-0.5/Makefile
        /usr/lib/gcc/x86_64-linux-gnu/4.6/include-fixed/limits.h
        /home/nexb/tools/patchelf/patchelf-0.5/tests/.deps/main.Po
        /home/nexb/tools/patchelf/patchelf-0.5/src/Makefile
        /home/nexb/tools/patchelf/patchelf-0.5/tests/.deps/simple.Po
        /usr/lib/gcc/x86_64-linux-gnu/4.6/include/stdarg.h
        /usr/lib/gcc/x86_64-linux-gnu/4.6/include/stdint.h
        /usr/lib/gcc/x86_64-linux-gnu/4.6/include/stddef.h
        /home/nexb/tools/patchelf/patchelf-0.5/tests/Makefile
        /home/nexb/tools/patchelf/patchelf-0.5/tests/.deps/big-dynstr.Po
        /usr/lib/gcc/x86_64-linux-gnu/4.6/include-fixed/syslimits.h
        /home/nexb/tools/patchelf/patchelf-0.5/src/elf.h
        /home/nexb/tools/patchelf/patchelf-0.5/src/patchelf.cc""".split()

        assert sorted(list(sources)) == sorted(expected_srcs)

        expected_tgts = [
            "/home/nexb/tools/patchelf/patchelf-0.5/src/patchelf",
            "/tmp/ccDO5gyj.c",
            "/tmp/ccHpGGfn.o",
            "/tmp/ccj50xXq.ld",
            "/tmp/ccxlsgGu.le",
        ]
        assert expected_tgts == sorted(list(targets))

    def test_guess_sources_and_targets_for_patchelf_with_default_settings(self):
        cwd = "/home/nexb/tools/patchelf/patchelf-0.5"
        test_name = "analy_patchelf_settings"

        input_dir = self.extract_trace(test_name)
        output_dir = None

        extra_read_ignored = ("/usr/lib/gcc/*",) + conf.GCC_DEPEND_FILES + conf.GCC_INCLUDES
        stgs = conf.DefaultSettings()
        stgs.ignored_reads += extra_read_ignored
        stgs.ignored_writes += conf.GCC_DEPEND_FILES
        procs = tracecode.parse_raw_traces(cwd, input_dir, output_dir, parallel=True, settings=stgs)

        sources, targets = tracecode.guess_sources_and_targets(procs)
        expected_srcs = """/home/nexb/tools/patchelf/patchelf-0.5/Makefile
        /home/nexb/tools/patchelf/patchelf-0.5/src/Makefile
        /home/nexb/tools/patchelf/patchelf-0.5/tests/Makefile
        /home/nexb/tools/patchelf/patchelf-0.5/src/elf.h
        /home/nexb/tools/patchelf/patchelf-0.5/src/patchelf.cc""".split()
        assert sorted(expected_srcs) == sorted(sources)

        expected_tgts = [
            "/home/nexb/tools/patchelf/patchelf-0.5/src/patchelf",
            "/tmp/ccDO5gyj.c",
            "/tmp/ccHpGGfn.o",
        ]
        assert sorted(expected_tgts) == sorted(targets)

    def test_guess_sources_and_targets_from_dir(self):
        cwd = "/home/nexb/tools/patchelf/patchelf-0.5"
        test_name = "analy_patchelf_settings2"

        input_dir = self.extract_trace(test_name)
        output_dir = self.get_temp_dir()

        extra_read_ignored = (
            (
                "/usr/lib/gcc/*",
                "*/Makefile",
            )
            +conf.GCC_DEPEND_FILES
            +conf.GCC_INCLUDES
        )
        stgs = conf.DefaultSettings()
        stgs.ignored_reads += extra_read_ignored
        stgs.ignored_writes += conf.GCC_DEPEND_FILES
        tracecode.parse_raw_traces(cwd, input_dir, output_dir, parallel=True, settings=stgs)
        sources, targets = tracecode.guess_sources_and_targets_from_dir(dir_path=output_dir)
        expected_srcs = """/home/nexb/tools/patchelf/patchelf-0.5/src/elf.h
        /home/nexb/tools/patchelf/patchelf-0.5/src/patchelf.cc""".split()
        assert sorted(sources) == sorted(expected_srcs)

        expected_tgt = sorted(
            """/home/nexb/tools/patchelf/patchelf-0.5/src/patchelf
                     /tmp/ccDO5gyj.c
                     /tmp/ccHpGGfn.o""".split()
        )
        assert sorted(list(targets)) == expected_tgt

    def test_inventory(self):
        input_dir = self.extract_trace("inventory")
        output_dir = None
        stgs = conf.Settings(
            cwd=None, multiplexers=[], errors=[], ignored_reads=tuple(), ignored_writes=tuple()
        )

        cwd = None
        procs = tracecode.parse_raw_traces(
            cwd, input_dir, output_dir, parallel=False, settings=stgs, clean=False
        )
        results = sorted(
            (
                p,
                str(r),
                str(w),
            )
            for p, r, w in tracecode.file_rw_counts(procs)
        )

        expect_pth = self.get_tst_path("inventory/expected")
        if _GLOBAL_REGEN:
            with open(expect_pth) as csvfile:
                for item in results:
                    csvfile.write(",".join(item) + "\n")
        expected = open(expect_pth).read().splitlines()
        expected = sorted(tuple(i.split(",")) for i in expected)
        assert results == expected


class TraceFullGraphAnalysisTest(BaseTestCase):

    def test_file_sets_sources_and_targets_in_graph(self):
        input_dir = self.extract_trace("file_graph_analysis_patchelf")
        output_dir = None
        stgs = conf.Settings(
            cwd=None,
            multiplexers=[],
            errors=[],
            ignored_reads=tuple(),
            ignored_writes=tuple(),
            sources=(
                "/home/nexb/tools/patchelf/patchelf-0.5/src/elf.h",
                "/home/nexb/tools/patchelf/patchelf-0.5/src/patchelf.cc",
            ),
            targets=("/home/nexb/tools/patchelf/patchelf-0.5/src/patchelf",),
        )

        procs = tracecode.parse_raw_traces(
            None, input_dir, output_dir, parallel=False, settings=stgs, clean=True
        )
        graph = tracecode.as_file_graph(procs, stgs)
        srcs, tgts, ints = tracecode.file_sets(graph, stgs)

        expected_srcs = (
            open(self.get_tst_path("file_graph_analysis_patchelf/expected_srcs"))
            .read()
            .splitlines()
        )
        assert sorted(list(srcs)) == sorted(expected_srcs)

        expected_tgts = (
            open(self.get_tst_path("file_graph_analysis_patchelf/expected_tgts"))
            .read()
            .splitlines()
        )
        assert sorted(list(tgts)) == sorted(expected_tgts)

        expected_ints = (
            open(self.get_tst_path("file_graph_analysis_patchelf/expected_ints"))
            .read()
            .splitlines()
        )
        assert sorted(list(ints)) == sorted(expected_ints)

    def test_node_sets_sources_and_targets_in_graph(self):
        input_dir = self.extract_trace("file_graph_analysis_patchelf")
        output_dir = None
        stgs = conf.Settings(
            cwd=None,
            multiplexers=[],
            errors=[],
            ignored_reads=tuple(),
            ignored_writes=tuple(),
            sources=(
                "/home/nexb/tools/patchelf/patchelf-0.5/src/elf.h",
                "/home/nexb/tools/patchelf/patchelf-0.5/src/patchelf.cc",
            ),
            targets=("/home/nexb/tools/patchelf/patchelf-0.5/src/patchelf",),
        )

        procs = tracecode.parse_raw_traces(
            None, input_dir, output_dir, parallel=False, settings=stgs, clean=True
        )
        graph = tracecode.as_graph(procs, stgs)
        srcs, tgts, ints = tracecode.node_sets(graph, stgs)

        def paths(nset):
            return set(graph.node_data(n).path for n in nset)

        srcs = paths(srcs)
        tgts = paths(tgts)
        ints = paths(ints)

        expected_srcs = (
            open(self.get_tst_path("file_graph_analysis_patchelf/expected_srcs"))
            .read()
            .splitlines()
        )
        assert sorted(list(srcs)) == sorted(expected_srcs)

        expected_tgts = (
            open(self.get_tst_path("file_graph_analysis_patchelf/expected_tgts"))
            .read()
            .splitlines()
        )
        assert sorted(list(tgts)) == sorted(expected_tgts)

        expected_ints = (
            open(self.get_tst_path("file_graph_analysis_patchelf/expected_ints"))
            .read()
            .splitlines()
        )
        assert sorted(list(ints)) == sorted(expected_ints)

    def test_analyze_file_graph_patchelf_d2d_with_default_settings(self):
        cwd = "/home/nexb/tools/patchelf/patchelf-0.5"
        test_name = "d2d_patchelf_settings"

        input_dir = self.extract_trace(test_name)
        output_dir = None

        # also ignore makefiles
        extra_read_ignored = (
            (
                "/usr/lib/gcc/*",
                "*/Makefile",
            )
            +conf.GCC_DEPEND_FILES
            +conf.GCC_INCLUDES
        )
        stgs = conf.DefaultSettings()

        sources = (
            "/home/nexb/tools/patchelf/patchelf-0.5/src/elf.h",
            "/home/nexb/tools/patchelf/patchelf-0.5/src/patchelf.cc",
        )
        targets = ("/home/nexb/tools/patchelf/patchelf-0.5/src/patchelf",)

        stgs.ignored_reads += extra_read_ignored
        stgs.ignored_writes += conf.GCC_DEPEND_FILES
        stgs.sources = sources
        stgs.targets = targets
        procs = tracecode.parse_raw_traces(cwd, input_dir, output_dir, parallel=True, settings=stgs)

        d2d = tracecode.analyze_file_graph(procs, settings=stgs)
        d2d = sorted(d2d)

        expected = sorted(
            [
                (
                    "/home/nexb/tools/patchelf/patchelf-0.5/src/patchelf.cc",
                    "/home/nexb/tools/patchelf/patchelf-0.5/src/patchelf",
                ),
                (
                    "/home/nexb/tools/patchelf/patchelf-0.5/src/elf.h",
                    "/home/nexb/tools/patchelf/patchelf-0.5/src/patchelf",
                ),
            ]
        )
        assert d2d == expected

    def analyze_d2d(self, test_name, cwd, settings, expected=None, regen=False):

        input_dir = self.extract_trace(test_name)
        procs = tracecode.parse_raw_traces(cwd, input_dir, None, parallel=True, settings=settings)

        d2d = tracecode.analyze_full_graph(procs, settings, _invert=None)
        d2d = sorted(set(d2d))
        expect_pth = self.get_tst_path(test_name + "/expected")
        if regen or _GLOBAL_REGEN:
            with open(expect_pth, "w") as csvfile:
                wrtr = csv.writer(csvfile)
                for src_tgt in d2d:
                    wrtr.writerow(src_tgt)

        if not expected:
            expected = open(expect_pth).read().splitlines()
            expected = sorted([tuple(ex.split(",")) for ex in expected])
            expected = [
                (
                    None if not x else x,
                    None if not y else y,
                )
                for x, y in expected
            ]
        assert d2d == expected

        # test also the walks inverted
        d2d = tracecode.analyze_full_graph(procs, settings, _invert=True)
        d2d = sorted(set(d2d))
        assert d2d == expected

    def _get_file_set(self, test_name, name):
        fs = self.get_tst_path(join(test_name, name))
        return set(f for f in open(fs).read().splitlines() if f)

    def test_analyze_full_graph_patchelf_d2d_with_default_settings(self):
        cwd = "/home/nexb/tools/patchelf/patchelf-0.5"
        test_name = "d2d_patchelf_settings"

        stgs = conf.DefaultSettings()
        # ignore makefiles
        extra_read_ignored = (
            (
                "/usr/lib/gcc/*",
                "*/Makefile",
            )
            +conf.GCC_DEPEND_FILES
            +conf.GCC_INCLUDES
        )
        stgs.ignored_reads += extra_read_ignored
        stgs.ignored_writes += conf.GCC_DEPEND_FILES

        stgs.sources = (
            "/home/nexb/tools/patchelf/patchelf-0.5/src/elf.h",
            "/home/nexb/tools/patchelf/patchelf-0.5/src/patchelf.cc",
        )
        stgs.targets = ("/home/nexb/tools/patchelf/patchelf-0.5/src/patchelf",)

        expected = sorted(
            [
                (
                    "/home/nexb/tools/patchelf/patchelf-0.5/src/patchelf.cc",
                    "/home/nexb/tools/patchelf/patchelf-0.5/src/patchelf",
                ),
                (
                    "/home/nexb/tools/patchelf/patchelf-0.5/src/elf.h",
                    "/home/nexb/tools/patchelf/patchelf-0.5/src/patchelf",
                ),
            ]
        )

        self.analyze_d2d(test_name, cwd, settings=stgs, expected=expected)

    def test_analyze_strace_d2d_with_default_settings(self):
        cwd = "/home/nexb/tools/strace/strace-4.8"
        test_name = "d2d_strace_settings"
        stgs = conf.DefaultSettings()
        extra_read_ignored = (
            (
                "/usr/lib/gcc/*",
                "*/Makefile",
            )
            +conf.GCC_DEPEND_FILES
            +conf.GCC_INCLUDES
        )
        stgs.ignored_reads += extra_read_ignored
        stgs.ignored_writes += conf.GCC_DEPEND_FILES
        stgs.sources = self._get_file_set(test_name, "sources")
        stgs.targets = ("/home/nexb/tools/strace/strace-4.8/strace",)
        self.analyze_d2d(test_name, cwd, settings=stgs, regen=False)

    def test_analyze_cups_d2d_with_default_settings(self):
        cwd = "/home/nexb/tools/strace/strace-4.8"
        test_name = "d2d_cups_settings"

        stgs = conf.DefaultSettings()
        extra_read_ignored = (
            (
                "/usr/lib/gcc/*",
                "*/Makefile",
                "*/cups/Dependencies",
                "*/Makedefs",
            )
            +conf.GCC_DEPEND_FILES
            +conf.GCC_INCLUDES
        )
        stgs.ignored_reads += extra_read_ignored
        stgs.ignored_writes += conf.GCC_DEPEND_FILES

        stgs.sources = self._get_file_set(test_name, "sources")
        targets = set(
            """/home/nexb/tools/cups/cups-1.4.6/backend/libbackend.a
                    /home/nexb/tools/cups/cups-1.4.6/cgi-bin/libcupscgi.a
                    /home/nexb/tools/cups/cups-1.4.6/cups/libcups.a
                    /home/nexb/tools/cups/cups-1.4.6/driver/libcupsdriver.a
                    /home/nexb/tools/cups/cups-1.4.6/filter/libcupsimage.a
                    /home/nexb/tools/cups/cups-1.4.6/ppdc/libcupsppdc.a
                    /home/nexb/tools/cups/cups-1.4.6/scheduler/libcupsmime.a
                    """.split()
        )
        stgs.targets = targets

        self.analyze_d2d(test_name, cwd, settings=stgs, regen=False)

    @pytest.mark.skipif(on_windows, reason="This fails on Windows for unknown reasons")
    def test_analyze_multiplexed_copy_d2d(self):
        test_name = "d2d_multiplexed_cp"
        stgs = conf.BaseSettings()
        stgs.sources = self._get_file_set(test_name, "src.lst")
        stgs.targets = self._get_file_set(test_name, "tgt.lst")
        cwd = "/home/pombredanne/bin/tracecode"
        self.analyze_d2d(test_name, cwd=cwd, settings=stgs, regen=True)


class DumpTest(BaseTestCase):

    def test_dump(self):
        cwd = "/home/nexb/tools/patchelf/patchelf-0.5"
        test_name = "dump_patchelf"

        input_dir = self.extract_trace(test_name)
        output_dir = None
        stgs = conf.DefaultSettings()
        procs = tracecode.parse_raw_traces(cwd, input_dir, output_dir, parallel=True, settings=stgs)
        resdir = self.get_temp_dir(False)
        resloc = join(resdir, "dumped.csv")
        tracecode.dump_procs_to_csv(procs, resloc, stgs)
        results = open(resloc).read()
        exploc = self.get_tst_path("dump_patchelf/expected.csv")
        regen = False
        if regen:
            shutil.copy(resloc, exploc)
        expected = open(exploc).read()
        assert sorted(l for l in results.splitlines() if l) == sorted(expected.splitlines())


class ConfTest(BaseTestCase):

    def test_Settings_object_can_be_pickled(self):
        stgs = conf.DefaultSettings()
        import pickle

        sd = pickle.dumps(stgs)
        sl = pickle.loads(sd)
        assert sl.dict() == stgs.dict()

    def test_formatted(self):
        expected = """format=pdf

sources=one
  two
  -three*

targets=somefile
  someotherfile
"""
        args = {
            "sources": (
                "one",
                "two",
                "-three*",
            ),
            "targets": (
                "somefile",
                "someotherfile",
            ),
        }
        stgs = conf.BaseSettings(**args)
        assert stgs.formatted() == expected

    def test_args_subset(self):
        assert conf.args_subset({}) == {}

    def test_combined_settings_are_never_empty(self):
        stgs = conf.settings(args={})
        assert None != stgs
        expected = conf.BaseSettings()
        assert stgs.dict() == expected.dict()


class TestPathUtils(unittest.TestCase):

    def test_common_path_prefix1(self):
        test = pathutils.common_path_prefix("/a/b/c", "/a/b/c")
        assert test == ("a/b/c", 3)

    def test_common_path_prefix2(self):
        test = pathutils.common_path_prefix("/a/b/c", "/a/b")
        assert test == ("a/b", 2)

    def test_common_path_prefix3(self):
        test = pathutils.common_path_prefix("/a/b", "/a/b/c")
        assert test == ("a/b", 2)

    def test_common_path_prefix4(self):
        test = pathutils.common_path_prefix("/a", "/a")
        assert test == ("a", 1)

    def test_common_path_prefix_path_root(self):
        test = pathutils.common_path_prefix("/a/b/c", "/")
        assert test == (None, 0)

    def test_common_path_prefix_root_path(self):
        test = pathutils.common_path_prefix("/", "/a/b/c")
        assert test == (None, 0)

    def test_common_path_prefix_root_root(self):
        test = pathutils.common_path_prefix("/", "/")
        assert test == (None, 0)

    def test_common_path_prefix_path_elements_are_similar(self):
        test = pathutils.common_path_prefix("/a/b/c", "/a/b/d")
        assert test == ("a/b", 2)

    def test_common_path_prefix_no_match(self):
        test = pathutils.common_path_prefix("/abc/d", "/abe/f")
        assert test == (None, 0)

    def test_common_path_prefix_ignore_training_slashes(self):
        test = pathutils.common_path_prefix("/a/b/c/", "/a/b/c/")
        assert test == ("a/b/c", 3)

    def test_common_path_prefix8(self):
        test = pathutils.common_path_prefix("/a/b/c/", "/a/b")
        assert test == ("a/b", 2)

    def test_common_path_prefix10(self):
        test = pathutils.common_path_prefix("/a/b/c.txt", "/a/b/b.txt")
        assert test == ("a/b", 2)

    def test_common_path_prefix11(self):
        test = pathutils.common_path_prefix("/a/b/c.txt", "/a/b.txt")
        assert test == ("a", 1)

    def test_common_path_prefix12(self):
        test = pathutils.common_path_prefix("/a/c/e/x.txt", "/a/d/a.txt")
        assert test == ("a", 1)

    def test_common_path_prefix13(self):
        test = pathutils.common_path_prefix("/a/c/e/x.txt", "/a/d/")
        assert test == ("a", 1)

    def test_common_path_prefix14(self):
        test = pathutils.common_path_prefix("/a/c/e/", "/a/d/")
        assert test == ("a", 1)

    def test_common_path_prefix15(self):
        test = pathutils.common_path_prefix("/a/c/e/", "/a/c/a.txt")
        assert test == ("a/c", 2)

    def test_common_path_prefix16(self):
        test = pathutils.common_path_prefix("/a/c/e/", "/a/c/f/")
        assert test == ("a/c", 2)

    def test_common_path_prefix17(self):
        test = pathutils.common_path_prefix("/a/a.txt", "/a/b.txt/")
        assert test == ("a", 1)

    def test_common_path_prefix18(self):
        test = pathutils.common_path_prefix("/a/c/", "/a/")
        assert test == ("a", 1)

    def test_common_path_prefix19(self):
        test = pathutils.common_path_prefix("/a/c.txt", "/a/")
        assert test == ("a", 1)

    def test_common_path_prefix20(self):
        test = pathutils.common_path_prefix("/a/c/", "/a/d/")
        assert test == ("a", 1)

    def test_common_path_suffix(self):
        test = pathutils.common_path_suffix("/a/b/c", "/a/b/c")
        assert test == ("a/b/c", 3)

    def test_common_path_suffix_absolute_relative(self):
        test = pathutils.common_path_suffix("a/b/c", "/a/b/c")
        assert test == ("a/b/c", 3)

    def test_common_path_suffix_find_subpath(self):
        test = pathutils.common_path_suffix("/z/b/c", "/a/b/c")
        assert test == ("b/c", 2)

    def test_common_path_suffix_handles_relative_path(self):
        test = pathutils.common_path_suffix("a/b", "a/b")
        assert test == ("a/b", 2)

    def test_common_path_suffix_handles_relative_subpath(self):
        test = pathutils.common_path_suffix("zsds/adsds/a/b/b/c", "a//a/d//b/c")
        assert test == ("b/c", 2)

    def test_common_path_suffix_ignore_and_strip_trailing_slash(self):
        test = pathutils.common_path_suffix("zsds/adsds/a/b/b/c/", "a//a/d//b/c/")
        assert test == ("b/c", 2)

    def test_common_path_suffix_return_None_if_no_common_suffix(self):
        test = pathutils.common_path_suffix("/a/b/c", "/")
        assert test == (None, 0)

    def test_common_path_suffix_return_None_if_no_common_suffix2(self):
        test = pathutils.common_path_suffix("/", "/a/b/c")
        assert test == (None, 0)

    def test_common_path_suffix_match_only_whole_segments(self):
        # only segments are honored, commonality within segment is ignored
        test = pathutils.common_path_suffix("this/is/aaaa/great/path", "this/is/aaaaa/great/path")
        assert test == ("great/path", 2)

    def test_common_path_suffix_two_root(self):
        test = pathutils.common_path_suffix("/", "/")
        assert test == (None, 0)

    def test_common_path_suffix_empty_root(self):
        test = pathutils.common_path_suffix("", "/")
        assert test == (None, 0)

    def test_common_path_suffix_root_empty(self):
        test = pathutils.common_path_suffix("/", "")
        assert test == (None, 0)

    def test_common_path_suffix_empty_empty(self):
        test = pathutils.common_path_suffix("", "")
        assert test == (None, 0)

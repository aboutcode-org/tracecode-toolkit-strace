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

"""
TraceCode: trace a command execution with strace.
"""

import errno
import getopt
import logging
import os
import subprocess
import sys

__version__ = "0.10.0"


logger = logging.getLogger("tracecode.trace")


def check_strace():
    pass


def check_disk_space():
    pass


def trace_command(cmd, output_dir):
    """
    Trace a command with strace.
    """
    prettycmd = " ".join(cmd)
    logging.info("Tracing %(prettycmd)r to %(output_dir)s" % locals())
    trace_cmd = [
        "strace",  # TODO: should be an absolute path
        "-ff",  # trace each process and children in a separate trace file
        "-y",  # decode file descs
        "-s",
        "256",  # get so many chars per args.
        "-a1",  # no alignment for results codes
        "-qq",  # suppress process exit messages
        "-ttt",  # full resolution time stamps
        "-o",
        os.path.join(output_dir, "t"),  # output dir and trace name of 't'
    ] + cmd

    logging.debug("trace command: " + " ".join(trace_cmd))
    # TODO: capture stdout and stderr: tee to terminal and save in files
    proc = subprocess.Popen(trace_cmd)
    out = proc.communicate()[0]
    return proc.returncode, out


def usage():

    print(
        """
Trace a command execution and write results to a directory.

Usage:
    tracer.py  -o DIR COMMAND
    tracer.py  -h | --help | -v | --version

Arguments:
    COMMAND: the command to trace.

Options:
  -o, --output DIR  Existing directory where tracing is saved.
  -v, --version     Display current version, license and copyright notice.
  -h, --help        Display help.
"""
    )


def version():
    print(
        """
TraceCode:tracer Version: %s
Copyright (c) nexB Inc. All rights reserved. https://github.com/nexB/tracecode-build
"""
        % __version__
    )


def check_dir(pth, label):
    if not os.path.exists(pth) or not os.path.isdir(pth):
        print("%s directory does not exist or is not a directory." % (label,))
        sys.exit(errno.EEXIST)


def check_dir_empty(pth, label):
    if os.listdir(pth):
        print("%s directory is not empty." % (label,))
        sys.exit(errno.EEXIST)


def main(args, opts):
    logging.basicConfig(level=logging.INFO)
    if not len(args) <= 1:
        usage()
        sys.exit(0)

    opt = args[0]
    if opt in ("-h", "--help"):
        usage()
        sys.exit(0)
    elif opt in ("-v", "--version"):
        version()
        sys.exit(0)
    elif opt not in ("-o", "--output"):
        usage()
        sys.exit(errno.EINVAL)

    if not len(args) <= 3:
        print("Output directory and command are mandatory.")
        usage()
        sys.exit(errno.EINVAL)

    odir = args[1]
    output_dir = os.path.abspath(os.path.normpath(os.path.expanduser(odir)))
    if not os.path.exists(output_dir) or not os.path.isdir(output_dir):
        print("Output directory %(odir)s does not exist or " "is not a directory." % locals())
        sys.exit(errno.EINVAL)
    if os.listdir(output_dir):
        print("Output directory %(odir)s must be empty." % locals())
        sys.exit(errno.EINVAL)

    command = args[2:]
    trace_command(
        output_dir,
        command,
    )


if __name__ == "__main__":
    longopts = [
        "help",
        "output",
        "version",
    ]
    try:
        opts, args = getopt.getopt(sys.argv[1:], "hvo", longopts)
    except Exception as e:
        print(repr(e))
        usage()
        sys.exit(errno.EINVAL)

    main(args, opts)

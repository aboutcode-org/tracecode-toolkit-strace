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
import os
import textwrap

"""
TraceCode configuration and settings
"""


# NOTE: globs patterns prefixed with - are excluded.
# when a list contains such items, the - excluded patterns have precedence
# this allow to express complex file sets compactly
# For instance with:
# sources = ['/nexb/src/*','-/nexb/src/*.so']
# all files in /nexb/src/ would be considered UNLESS they end up in .so

# globs for exes that can do multiplexed reads/writes
# for disjunct file ops in a single process
# typically this only applies to programs that can copy several input files
# to one output directory
# TODO: the javac compiler is heavily multiplexing
DEFAULT_MUXERS = [
    # the standard cp copy command
    "*/cp",
    "/bin/cp",
    "cp",
    # AOSP acp copy command:
    # https://github.com/android/platform_build/tree/master/tools/acp
    "*/acp",
    "acp",
    # gcp copy command: hhttp://wiki.goffi.org/wiki/Gcp/en
    "*/gcp",
    "gcp",
    # strip is sometimes multiplexed
    "*/strip",
]


# TODO: '????',  handle when a function is not known to strace
# and syscall_XXXX for unknown syscalls?
DEFAULT_ERRORS = [
    # --- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_EXITED, si_pid=3654298, si_status=0, si_utime=0, si_stime=0} ---
    # --- SIGPIPE {si_signo=SIGPIPE, si_code=SI_USER, si_pid=3908887, si_uid=1001} ---
    # --- SIGSEGV {si_signo=SIGSEGV, si_code=SEGV_ACCERR, si_addr=0x2aaaaaacf000} ---
    # and other similar signals
    r".*--- SIG.*",
    # +++ killed by SIGPIPE +++
    r".*\+\+\+ killed by .* \+\+\+$",
    # rare but this can happen
    r".*core dumped.*",
    # +++ exited with 141 +++
    # NOTE: exit code should be tracked if the process failed?? to return 0??
    r".*\+\+\+ exited with .* \+\+\+$",
    # futex(0x2aaaac4bd9d0, FUTEX_WAIT, 3963568, NULL) = ? <unavailable>
    r".* <unavailable>$",
    # exit_group(141) = ?
    r".* exit_group.* = .*$",
    # _exit(0) = ?
    r".* _exit\(.* = .*$",
    # futex(0x2aaaac4bd9d0, FUTEX_WAIT, 3663942, NULL <unfinished ...>
    # note that since we follow processes and get per-proc straces
    # futexes are typically the only unfinished business
    r".* <unfinished \.\.\.>$",
    # The following are found when a line ends with ")"
    # which happens for failed syscalls when there is an errno returned that
    # strace was able to decode
    # Note some succeeding fcntl or poll calls return flags enclosed in ().
    # It does not matter because these calls are no-op for file tracing
    # Note that unknown/existing files-related failed calls, are not interesting
    # yet these can make up to 50% of the traces
    # (No such file or directory)
    # (File exists)
    # (Not a directory)
    # (Bad file descriptor)
    # (To be restarted)
    # (To be restarted if SA_RESTART is set)
    # (Invalid argument)
    # (Illegal seek)
    # (Broken pipe)
    # (Permission denied)
    # (No child processes)
    # (Interrupted system call)
    # (Invalid argument)
    # (No data available)
    # (Machine is not on the network)
    # (Inappropriate ioctl for device)
    # (Operation not permitted)
    # and many more
    r"^.*\)$",
]

###############################################################################
# Default set of globs for paths that should be ignored

# /proc /dev and /etc are typically not part of the build
# TODO: what happens when a build is using some fakeroot??
SYS_CONFIG = (
    # ignore read/write to /dev/pts, tty and similar
    "/dev/*",
    # etc files are not useful build wise: ld.confs and similar do
    # not participate in the build
    "/etc/*",
    # proc files are not useful
    "/proc/*",
)

# most bin/* and so's are not part of the build proper but used in tools
# TODO: these should be optional, as they may be
# though this could be wrong when doing an install
# .a libs could be part of the build
# part of the build proper when building for a host on the host
READ_BINS = (
    # no trailing / to include 32 and 64 variants
    "/lib*.so*",
    # no trailing / to include 32 and 64 variants
    "/usr/lib*.so*",
    # no trailing / to include 32 and 64 variants
    "/usr/local/lib*.so*",
    "/bin*",
    "/sbin*",
    "/usr/bin*",
    "/usr/sbin*",
    "/usr/local/bin*",
    "/usr/local/sbin*",
)


STD_INCLUDES = (
    "/usr/include*",
    "/usr/local/include*",
)


GCC_INCLUDES = ("/usr/lib/gcc/*",)


COMMON_GLIBC_AND_GCC_SHIMS = (
    "/usr/lib/*/crt1.o",
    "/usr/lib/*/crti.o",
    "/usr/lib/gcc/*/crtbegin.o",
    "/usr/lib/*/libgcc.a",
    "/usr/lib/*/libc_nonshared.a",
    "/usr/lib/gcc/*/crtend.o",
    "/usr/lib/*/crtn.o",
)

# These are temp dep files created by GCC
GCC_DEPEND_FILES = (
    "*/.deps/*/*.Tpo",
    "*/.deps/*.po",
    "*/.deps/*.Po",
    "*.Po",
    "*.po",
    "*.Tpo",
    "/tmp/*.le",
    "/tmp/*.ld",
    "*.o.d",
)

PERFDATA = ("/tmp/hsperfdata_*",)


DEFAULT_IGNORED_READS = list(
    SYS_CONFIG + READ_BINS + STD_INCLUDES + COMMON_GLIBC_AND_GCC_SHIMS + PERFDATA
)

DEFAULT_IGNORED_WRITES = list(SYS_CONFIG + PERFDATA)


# list of ignored executables command paths
DEFAULT_IGNORED_EXECS = []


# Fields used in settings definitions
#####################################
# name: the name of a setting key
# default: the default value for this key
# arg: the command line argument
# desc: the documentation for the corresponding command line argument
Field = collections.namedtuple("Field", "name default arg desc")

# fields with None name are only used as args/options and not settings
# fields with None arg are only used as internal settings

# settings that are also command line options
PUBLIC_OPTIONS = [
    Field(
        "ignored_reads",
        tuple(),
        "--ignored_reads=PATTERN",
        """Ignore reads paths matching PATTERN.""",
    ),
    Field(
        "ignored_reads_from",
        None,
        "--ignored_reads_from=FILE",
        """Ignore reads paths matching multiple PATTERNs
          loaded from FILE, one per line.""",
    ),
    Field(
        "ignored_writes",
        tuple(),
        "--ignored_writes=PATTERN",
        """Ignore writes paths matching PATTERN.""",
    ),
    Field(
        "ignored_writes_from",
        None,
        "--ignored_writes_from=FILE",
        """Ignore writes paths matching multiple PATTERNs
          loaded from FILE, one per line.""",
    ),
    Field(
        "ignored_execs",
        tuple(),
        "--ignored_execs=PATTERN",
        """Ignore executable paths matching PATTERN.""",
    ),
    Field(
        "ignored_execs_from",
        None,
        "--ignored_execs_from=FILE",
        """Ignore executable paths matching multiple PATTERNs
          loaded from FILE, one per line.""",
    ),
    Field("sources", tuple(), "--sources=PATH", """Use single PATH as sources."""),
    Field(
        "sources_from",
        None,
        "--sources_from=FILE",
        """Use the paths loaded from FILE as sources, one per line.""",
    ),
    Field("targets", tuple(), "--targets=PATH ...", """Use single PATH as targets."""),
    Field(
        "targets_from",
        None,
        "--targets_from=FILE",
        """Use the paths loaded from FILE as targets, one per line.""",
    ),
    Field(
        "format",
        "pdf",
        "--format=pdf|png|dot",
        """Set the output format for graphics: one of pdf, png
          or dot (graphviz). [default: pdf]""",
    ),
    Field("forks", False, "--forks", "Include processes that only fork other processes."),
    Field("stats", False, "--stats", """Print syscall statistics when parsing"""),
]


INTERNAL_SETTINGS = [
    # These are not exposed as command line arguments
    Field(
        "multiplexers",
        [],
        None,
        """Path pattern(s) matching executable paths that multiplex reads
          and writes in one step. These are executables that combine several
          unrelated reads and writes for unrelated files in one process such
          as the cp copy command or the javac compiler.""",
    ),
    Field(
        "errors",
        [],
        None,
        """Regex(s) matching a raw trace line to ignore because the syscall
          returned an error.""",
    ),
]


# some command line options are not settings and used only at the command line
PURE_OPTIONS = [
    Field(
        None,
        None,
        "--cwd=BASE_DIR",
        """Initial current/base working directory of the traced command,
          used to resolve relative paths as absolute paths. Used by commands
          parsing raw traces. If not provided, the base directory is inferred
          and some relative paths may not be resolved correctly.""",
    ),
    Field(
        None,
        False,
        "--defaults",
        """Use default filters. See defaults command to print defaults.""",
    ),
    Field(
        None, None, "--pid=PID", """With the debug command, only print the process with this PID."""
    ),
    Field(None, False, "--debug", """Include debug details in some commands ouput."""),
    Field(None, False, "-q, --quiet", "Suppress information messages."),
    Field(None, False, "-h, --help", "Show this help."),
    Field(None, False, "-v, --version", "Print current version."),
    Field(None, False, "-n, --notice", "Print version and copyright notice."),
]


def format_doc(fields):
    """
    Return a formatted doc string for a sequence of fields. Used to display as
    command line documentation and for docopt creation.
    """

    # get the length of the longest arg
    arg_len = max(len(f.arg) for f in fields)
    # we format the doc to look like this
    # thanks to textwrap for the heavy lifting:
    #  -c, --config=FILE           Use settings stored in config file.
    #  -                           if configuration file, blabla, etc
    # ^^               ^           ^                              ^
    # 01               arg_len     arg_len + 4                    max_width
    max_line_width = 79
    doc = []

    for sf in fields:
        line = (" %(arg)-" + str(arg_len) + "s ") % sf._asdict()
        ll = len(line)
        desc_width = max_line_width - ll
        wdesc = textwrap.wrap(" ".join(sf.desc.split()), desc_width)
        # first line is arg + description
        line = line + wdesc[0]
        doc.append(line)
        # other lines are description only
        for d in wdesc[1:]:
            line = " " * ll + d
            doc.append(" " * ll + d)
    return "\n".join(doc)


# this is used for the command line documentation
FORMATTED_OPTIONS = format_doc(PUBLIC_OPTIONS + PURE_OPTIONS)


# the main settings object, a namedtuple-like object but mutable
# ATTENTION: settings MUST pickle-able for multiprocessing
class Settings(object):
    def __init__(self, **kwargs):
        initial = dict(
            (
                f.name,
                f.default,
            )
            for f in (PUBLIC_OPTIONS + INTERNAL_SETTINGS)
        )
        self.__dict__.update(initial)
        self.__dict__.update(**kwargs)

    def dict(self):
        return dict(self.__dict__)

    def __repr__(self):
        from pprint import pformat

        return "Settings(%s)" % pformat(
            self.__dict__,
        )

    def merge(self, **kwargs):
        """
        Merge the kwargs key/values with self.
        """
        if not kwargs:
            return
        self.__dict__.update(kwargs)

    def formatted(self):
        """
        Return a formatted string representation of the public settings.
        """
        out = []
        priv_sets = set(f.name for f in INTERNAL_SETTINGS)
        pub_sets = dict(
            [
                (
                    k,
                    v,
                )
                for k, v in self.dict().items()
                if k not in priv_sets
            ]
        )

        # These options accept a list, and we know this: they default to an
        # empty list
        lists = set(
            f.name
            for f in PUBLIC_OPTIONS
            if f.default
            in (
                [],
                tuple(),
            )
        )
        for name, value in sorted(pub_sets.items()):
            if not value:
                continue
            if name in lists:
                first = value[0]
                out.append("%(name)s=%(first)s" % locals())
                for item in value[1:]:
                    out.append("  %(item)s" % locals())
            elif isinstance(value, bool):
                out.append("%(name)s" % locals())
            else:
                out.append("%(name)s=%(value)s" % locals())
            out.append("")
        return "\n".join(out)


def BaseSettings(**kwargs):
    s = Settings(multiplexers=tuple(DEFAULT_MUXERS), errors=tuple(DEFAULT_ERRORS), **kwargs)
    return s


def DefaultSettings(**kwargs):
    return BaseSettings(
        ignored_reads=tuple(DEFAULT_IGNORED_READS),
        ignored_writes=tuple(DEFAULT_IGNORED_WRITES),
        ignored_execs=tuple(DEFAULT_IGNORED_EXECS),
        **kwargs
    )


def patterns_from_file(file_name):
    """
    Load a PATH_PATTERN list from a file, return a list. If file_name has a
    .csv extension, load file_name as a CSV and keeps only the first column.
    """
    if not file_name:
        return tuple()
    fn = os.path.abspath(os.path.normpath(os.path.expanduser(file_name)))
    assert os.path.exists(fn) and os.path.isfile(fn), (
        "Pattern file %(file_name)s does not " "exist or is not a file."
    ) % locals()
    if fn.endswith(".csv"):
        with open(file_name) as csvfile:
            rdr = csv.reader(csvfile)
            # first column
            return tuple(row[0] for row in rdr)
    else:
        with open(fn) as f:
            return tuple(l.strip() for l in f if l and l.strip())


def patterns(pat_list, pat_file_name):
    """
    Return a sorted sequence of unique patterns combining a patterns list from
    args and patterns loaded from a file.
    """
    pat_list = pat_list or []
    # ensuring that we always warps things in a list
    if isinstance(pat_list, str):
        pat_list = [pat_list]

    pats = set(pat_list)
    # There is a bug in docopt: https://github.com/docopt/docopt/issues/134
    # so we use a set
    from_file = set(patterns_from_file(pat_file_name))
    return tuple(sorted(pats | from_file))


def args_subset(args):
    """
    Return a subset of args that are public non-list settings in a settings-
    like kwargs dict.
    """
    # do not load 'list' options that contain multiple values
    settings_keys = set(s.name for s in PUBLIC_OPTIONS if s.default != tuple())
    # remove leading dash from options that have one
    no_dash = dict(
        [
            (
                k.lstrip("-"),
                v,
            )
            for k, v in args.items()
            if k and k.lstrip("-") in settings_keys
        ]
    )
    return no_dash


def settings(args=None):
    """
    Convert args to a settings object.
    """
    stgs = BaseSettings()
    if args:
        if args.get("--defaults"):
            stgs = DefaultSettings()
        subset = args_subset(args)
        stgs.merge(**subset)

        stgs.ignored_reads += patterns(
            args.get("--ignored_reads"), args.get("--ignored_reads_from")
        )

        stgs.ignored_writes += patterns(
            args.get("--ignored_writes"), args.get("--ignored_writes_from")
        )

        stgs.ignored_execs += patterns(
            args.get("--ignored_execs"), args.get("--ignored_execs_from")
        )

        stgs.sources += patterns(args.get("--sources"), args.get("--sources_from"))

        stgs.targets += patterns(args.get("--targets"), args.get("--targets_from"))
    return stgs

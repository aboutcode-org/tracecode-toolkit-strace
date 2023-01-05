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
TraceCode is a tool to analyze the graph of file transformations from a
traced command, typically a build command.
"""

import collections
import copy
import errno
import fnmatch
import functools
import itertools
import logging
import multiprocessing
import os
import pickle
import posixpath
import re
import shlex
import subprocess
import sys
import time
from queue import Empty as Queue_Empty
from queue import Queue

from tracecode import conf
from tracecode import pathutils

# use a large compiled regex cache to avoid having to cache regex compilations
re._MAXCACHE = 1000000

__version__ = "0.10.0"


logger = logging.getLogger("tracecode")


def validate_traces(input_dir):
    """
    Check the raw trace files in input_dir for consistency and correctness.
    Return the root process pid and a map of pid-> trace file path .
    """
    traces = {}
    trace_name = None
    root_trace = None
    oldest_ts = None
    oldest_pid = None
    for filename in os.listdir(input_dir):
        path = os.path.join(input_dir, filename)
        # check that the we have only file
        if filename in (".svn", ".git", ".hg"):
            continue
        isfile_msg = (
            "validate_traces: %(path)r is not a regular file, " "does not exist or cannot be read."
        )
        assert os.path.isfile(path), isfile_msg % locals()

        # the strace per process files are named <trace_name>.<pid>
        # for instance mytrace.711873
        # check these follow the <trace_name>.<pid> convention
        tn, pid = filename.rsplit(".", 1)
        pid = pid.strip()
        digit_msg = "validate_traces: %(path)r is not a valid trace file."
        assert pid.isdigit(), digit_msg % locals()
        pid = int(pid)
        # and are all for the same trace name
        if not trace_name:
            trace_name = tn
        tn_msg = (
            "validate_traces: %(path)r is not part of the trace "
            "%(trace_name)r: wrong file name prefix"
        )
        assert tn == trace_name, tn_msg % locals()

        # find the oldest trace PID
        with open(path) as tf:
            # read the first line only to extract the first ts
            ts = None
            for l in tf:
                ts = l.split(" ", 1)
                break

            if ts and len(ts) >= 1:
                ts = float(ts[0])

                if oldest_ts:
                    if ts <= oldest_ts:
                        oldest_ts = ts
                        oldest_pid = pid
                else:
                    oldest_ts = ts
                    oldest_pid = pid

        # store a process trace by id
        traces[pid] = path

    # find the root process trace based on smallest pid
    # this can be wrong if there is a pid rollover
    smallest_pid = sorted(traces.keys())[0]
    root_pid = smallest_pid
    if smallest_pid != oldest_pid:
        root_pid = oldest_pid
        logger.info(
            (
                "validate_traces: Process PID rollover: using root pid: "
                "%(oldest_pid)d instead of %(smallest_pid)d."
            )
            % locals()
        )

    traces_len = len(traces)
    logger.info(
        ("validate_traces: Found %(traces_len)d traces with root " "pid: %(root_pid)r.") % locals()
    )
    logger.info(("validate_traces: Oldest pid: %(oldest_pid)r.") % locals())
    logger.info(("validate_traces: Smallest pid: %(smallest_pid)r.") % locals())
    return root_pid, traces


def as_list(q):
    """Convert a Queue to a list."""
    nq = copy.copy(q)
    return [nq.get() for _ in range(nq.qsize())]


def compute_timeout(traces_len):
    """
    Compute a timeout based on the number of process traces files to parse.

    We can timeout if we have a long time required for processing so we
    adapt the timeout to the number of trace files we are processing
    and we build a timeout derived from the number of trace files:
        base TIMEOUT + 1 sec for each XX traces
    """
    # all times are in seconds
    minimal_timeout = 120

    # traces
    wait_one_second_for_each = 100
    return int(minimal_timeout + (traces_len / wait_one_second_for_each))


def parse_raw_traces(
    cwd,
    input_dir,
    output_dir=None,
    settings=None,
    parallel=True,
    clean=True,
    timeout_func=compute_timeout,
):
    """
    Main function to parse raw traces. Process an input_dir of raw traces and
    write results in the output_dir directory. cwd is the base directory in
    which the traced command was executed initially, used for relative paths
    resolution. If parallel is True, multi-processing is used. Note:
    parallel=False is used mostly for testing and debugging.
    """
    # for debugging only
    # parallel = False
    settings = settings or conf.DefaultSettings()
    start = time.time()
    logger.info(
        (
            "Processing traces with cwd: %(cwd)r, "
            "input_dir: %(input_dir)r, "
            "output_dir: %(output_dir)r."
        )
        % locals()
    )

    root_pid, traces = validate_traces(input_dir)

    if output_dir:
        # in tests, output_dir can be None
        output_dir = os.path.normpath(os.path.expanduser(output_dir))
        output_dir = os.path.abspath(output_dir)
        if not os.path.exists(output_dir):
            logger.info("Creating output dir: %(output_dir)r." % locals())
            os.makedirs(output_dir)

    # At this stage we have: the root_process_pid, traces, and a mapping
    # of pid -> trace file path

    # TODO: create sub-dirs based on the number of traces to have at most a
    # few 100 to 1000 files per dir

    # queues of things todo and things done
    manager = multiprocessing.Manager()
    todo = manager.Queue()
    done = manager.Queue()
    # use a rather high number of processes/threads: x times the number of CPU
    # cores
    if parallel:
        pool = multiprocessing.Pool(multiprocessing.cpu_count() * 2)

    # we start from the root pid
    root_proc = Process(pid=root_pid, ppid=None, cwd=cwd, init_exec=None)
    todo.put(root_proc)

    # track if some process traces are unrelated to the process tree
    has_orphans = False
    traces_len = len(traces)

    timeout = timeout_func(traces_len)

    for i in range(traces_len):

        # if we have orphaned traces, we will timeout eventually
        try:
            proc = todo.get(block=True, timeout=timeout)
        except Queue_Empty:
            # TODO: report some details on the error: here we likely have
            # trace files that are not part of the trace graph and their PID
            # shows nowhere
            has_orphans = True
            break
        trace_file = traces[proc.pid]
        logger.info(
            "Queuing trace of pid %r for parsing. Left to do: %r"
            % (
                proc.pid,
                traces_len - i - 1,
            )
        )

        if parallel:
            # this is multi processed
            _res = pool.apply_async(
                func=parse_trace_file,
                args=(
                    proc,
                    trace_file,
                    todo,
                    done,
                    output_dir,
                    settings,
                ),
            )
        else:
            # we process serially, for debugging and tests
            _res = parse_trace_file(proc, trace_file, todo, done, output_dir, settings)

    # wait for all processes to complete
    duration = time.time() - start
    logger.info(
        "All %(traces_len)r traces queued for parsing " "in %(duration).2f seconds." % locals()
    )

    if parallel:
        pool.close()
        # there is a bug in multiprocessing in some Python 2.7 versions
        # http://bugs.python.org/issue15101
        # Exception RuntimeError: RuntimeError('cannot join current thread',)
        # this exception seems innocuous and happens in some test runs
        pool.join()
    duration = time.time() - start

    # we return a pid-sorted list
    if output_dir:
        key = lambda x: x
    else:
        key = lambda x: x.pid

    done = sorted(as_list(done), key=key)
    len_done = len(done)

    # we have trace files unrelated to the main graph of traces here
    if has_orphans:
        if output_dir:
            related_parsed_traces = set(done)
        else:
            related_parsed_traces = set([p.pid for p in done])

        # orphans are the pid we had in our dir initially BUT are not found in
        # the set of parsed, related traces graph
        orphans = [pid for pid in traces if pid not in related_parsed_traces]
        len_orphans = len(orphans)

        first_orphan_pid = orphans[0]

        # get the details of the first orphaned process
        first_orphan_proc = Process(pid=first_orphan_pid, ppid=None, cwd=None, init_exec=None)
        o_done = Queue()
        o_trace_file = traces[proc.pid]

        fake_todo = Queue()
        parse_trace_file(
            proc=first_orphan_proc,
            trace_file=o_trace_file,
            todo=fake_todo,
            done=o_done,
            output_dir=None,
            settings=settings,
        )
        first_orphan_repr = first_orphan_proc.pformat()

        logger.error(
            "INCOMPLETE TRACE, %(len_orphans)r orphaned trace(s) "
            "detected that are not related to the primary process "
            "graph. Smallest orphan pid is: %(first_orphan_pid)r:\n"
            "%(first_orphan_repr)s" % locals()
        )

    # print stats
    if settings.stats:
        if not output_dir:
            to_stat = done
        else:
            # rehydrate process objects if we have only pids
            to_stat = load(output_dir, done)
        stats = parsing_statistics(to_stat)
        logger.info("\n%(stats)s\n" % locals())

    # clean
    if not has_orphans and clean:
        # TODO: add some informative logging
        done = cleaner(done, input_dir=output_dir)

    logger.info(
        "Processing completed in %(duration).2f seconds. "
        "All %(len_done)d traces parsed and saved to: "
        '"%(output_dir)s".' % locals()
    )

    return done


def parse_trace_file(proc, trace_file, todo, done, output_dir=None, settings=None):
    """
    Parse a process `trace_file1 and update the `proc` Process object. Update
    the `todo` queue with new children Process objects that need further
    parsing.

    If `output_dir` is defined, save as a pickle the parsed `proc` Process
    object in the `output_dir` and put only the `proc` Process `pid` in the
    `done` queue. If `output_dir` is not defined, put the full `proc` Process
    object in the `done` queue.

    Use `settings` as needed to driver the parsing.

    NOTE: this function returns nothing and exchanges data only through the
    `todo` and `done` queues to support parallelization with multiprocessing.
    """
    settings = settings or conf.DefaultSettings()
    logger.debug(
        "parse_trace_file: proc:%(proc)r, "
        "trace_file:%(trace_file)r, "
        "output_dir:%(output_dir)r." % locals()
    )
    ln = 0
    current_line = None
    try:
        with open(trace_file) as trace:
            for line in trace:
                current_line = line
                child = parse_line(line, proc, settings)
                if child:
                    logger.debug("parse_trace_file: adding new child: " "%(child)r." % locals())
                    todo.put(child)
                ln += 1

        # always do basic cleaning
        proc.clean(settings)

        if output_dir:
            proc.dump(output_dir)
            done.put(proc.pid)
        else:
            done.put(proc)
    except Exception as e:
        msg = "In parse_trace_file for pid:%r at line %d: %r: %r" % (proc.pid, ln, current_line, e)
        logger.error(msg)
        raise
        return
    logger.debug("parse_trace_file: done for proc:%(proc)r." % locals())


def parsing_statistics(procs):
    """Return formatted parsing statistics from a list of processes."""
    failed_syscalls_count = 0
    line_parsing_errors_count = 0
    descriptor_warnings_count = 0
    per_syscall_counts = collections.defaultdict(int)
    unhandled_syscalls = set()
    for proc in procs:
        failed_syscalls_count += proc.failed_syscalls_count
        line_parsing_errors_count += proc.line_parsing_errors_count
        descriptor_warnings_count += proc.descriptor_warnings_count
        for k in proc.per_syscall_counts:
            per_syscall_counts[k] += proc.per_syscall_counts[k]
        unhandled_syscalls.update(proc.unhandled_syscalls)
    st = ["Parsing statistics", "=================="]
    st.append("Counters")
    st.append("--------")
    st.append("Ignored failed calls: %(failed_syscalls_count)r" % locals())
    st.append("Line parsing errors: %(line_parsing_errors_count)r" % locals())
    st.append("Descriptor warnings: %(descriptor_warnings_count)r" % locals())
    st.append("")
    st.append("Number of calls per syscall")
    st.append("---------------------------")
    for call in sorted(per_syscall_counts, key=lambda x: per_syscall_counts[x], reverse=True):
        cnt = per_syscall_counts[call]
        st.append("%(call)s: %(cnt)r" % locals())
    st.append("")
    st.append("Unhandled syscalls")
    st.append("------------------")
    for call in sorted(unhandled_syscalls):
        st.append(call)
    return "\n".join(st)


################################
# SYSCALLS function prototypes reference
################################

# int execve(const char *filename, char *const argv[],char *const envp[]);

# clone, fork, vfork: their return code is a new PID
# pid_t vfork(void);

# int chdir(const char *path);
# int fchdir(int fd);

# int rename(const char *oldpath, const char *newpath);
# int renameat(int olddirfd, const char *oldpath, int newdirfd, const char *newpath);

# ssize_t read(int fd, void *buf, size_t count);
# ssize_t pread(int fd, void *buf, size_t count, off_t offset);
# ssize_t readv(int fd, const struct iovec *iov, int iovcnt);
# ssize_t preadv(int fd, const struct iovec *iov, int iovcnt, off_t offset);
# ssize_t readahead(int fd, off64_t offset, size_t count);

# ssize_t write(int fd, const void *buf, size_t count);
# ssize_t pwrite(int fd, const void *buf, size_t count, off_t offset);
# ssize_t writev(int fd, const struct iovec *iov, int iovcnt);
# ssize_t pwritev(int fd, const struct iovec *iov, int iovcnt,off_t offset);
# int truncate(const char *path, off_t length);
# int ftruncate(int fd, off_t length);

# void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset);

# Supported calls as sets
NEW_PROCESS_CALLS = set("vfork fork".split())
CLONE_CALLS = set(("clone",))
CHANGE_DIR_CALLS = set("getcwd chdir fchdir".split())
EXEC_CALLS = set(("execve",))
READ_CALLS = set("pread pread64 preadv read readahead readv".split())
# note: vmsplice is a write that only applies to pipes
WRITE_CALLS = set(
    """write writev pwrite pwrite64 pwritev ftruncate
                     ftruncate64 vmsplice""".split()
)

# TODO: open support could be a must
# we handle open calls only for write operations on files
# this really matters on zero-lengths file creation and only for correctness
# as these files do not do much
# i.e. no O_RDONLY or O_DIRECTORY
# openat paths with AT_FDCWD should be resolved rel to CWD
#
"""
1390219298.394635 open("/usr/lib/locale/locale-archive", O_RDONLY|O_CLOEXEC) = 3
1399652674.495349 openat(AT_FDCWD, "test_data/", O_RDONLY|O_NONBLOCK|O_DIRECTORY|O_CLOEXEC) = 3
"""

OPENAT_CALL = "openat"
OPEN_CALL = "open"

OPEN_READ_FLAGS = set("O_RDONLY".split())
OPEN_WRITE_FLAGS = set("O_WRONLY O_RDWR O_CREAT O_TRUNC O_APPEND".split())
OPEN_DIR_FLAGS = set("O_DIRECTORY".split())

# FIXME/TODO: close calls are essential to track for long running build
# temp files and pipes can be short lived and named the same even though
# they are different things over time

"""
"""
CLOSE_CALLS = set("close".split())


"""
pipe() creates a pipe, a unidirectional data channel that can be used
       for interprocess communication.  The array pipefd is used to return
       two file descriptors referring to the ends of the pipe.  pipefd[0]
       refers to the read end of the pipe.  pipefd[1] refers to the write
       end of the pipe.  Data written to the write end of the pipe is
       buffered by the kernel until it is read from the read end of the
       pipe.  For further details, see pipe(7).

1412061560.730203 pipe([5, 6]) = 0
1412061560.730800 close(6<pipe:[82592441]>) = 0
1412061560.730823 read(5<pipe:[82592441]>, ".sources.xZFtua\n", 128) = 16
1412061560.741771 fcntl(1<pipe:[81097852]>, F_DUPFD, 10) = 10
1412060892.345460 fcntl(5<pipe:[81098959]>, F_DUPFD, 10) = 11
1412061560.741822 dup2(5</program/.sources.xZFtua>, 1<pipe:[81097852]>) = 1
1412061560.741911 dup2(10<pipe:[81097852]>, 1</program/.sources.xZFtua>) = 1
"""
PIPE_CALLS = set("pipe pipe2".split())


# May be a useful marker in some cases (such as in ld, to separate reads on
# execve-related reads vs reads on files actually being linked such as .so)
# For exe compiled with glibc, all syscalls from the beginning of a trace
# until an arch_prctl call are read/writes related to loading the exec for
# execve r/w calls after the arch_prctl are done by the loaded exec proper
# This is not a hard rule, but rather a heuristic that can be useful if we
# wanted to track access to .so done by a process exeve'ing the linker after
# the arch_prctl syscall which are the signs of dynamic linking going on vs.
# access to some .so done before the arch_prctl syscall in the same process
# which would be about loading the .so that the linker needs itself to
# actually run.

"""
1390219298.394343 arch_prctl(ARCH_SET_FS, 0x2aaaaaae9b40) = 0
"""
ARCH_CALLS = set("arch_prctl".split())

# These calls connect one FD to another FD, and are essentially like a rename
# NOTE: we do NOT handle dup nor fcntl with DUP args calls because they just
# duplicate a descriptor: they do not connect old and new descriptors together
# yet these duplication of FDs may matter for pipe lifecycle tracking
DUP1_CALLS = set("dup".split())
FCNTL_CALLS = set("fcntl".split())

DUP_CALLS = set("dup2 dup3 tee".split())
SENDFILE_CALLS = set("sendfile sendfile64".split())

RENAME_CALLS = set("rename renameat ".split())

# symlinkat
# 1412060539.019122 symlinkat("dummytest.c", AT_FDCWD, "openssl-0.9.8y/test/rc5test.c") = 0

# note a sym/hard link call is similar to a rename call from a file tracing
# perspective: it relate one file to the other conceptually
# NOTE: linkat call has the same semantics as the renameat call
HARD_LINK_CALLS = set("link linkat".split())
SYM_LINK_CALLS = set("symlink symlinkat".split())


# all these calls have read arg0/ and write arg1 (at these positions after arg
# normalization at least)
READ_WRITE_CALLS = RENAME_CALLS | SYM_LINK_CALLS | HARD_LINK_CALLS | DUP_CALLS | SENDFILE_CALLS

# Untraced / Unused for now
# Links and dir creation do not matter: we track files writes and read
DIR_CALLS = set("mkdir mkdirat rmdir".split())

READ_LINK_CALLS = set("readlink readlinkat".split())


DELETE_CALLS = set("unlink unlinkat".split())

# TODO: add support for mmap reads and writes that do reads and writes without
# a read or write call
"""
1390219298.394213 mmap(0x2aaaab085000, 24576, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3</lib/x86_64-linux-gnu/libc-2.15.so>, 0x1b5000) = 0x2aaab085000
1390219298.394241 mmap(0x2aaaab08b000, 17624, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS, -1, 0) = 0x2aaaab08b000
1390219298.394265 close(3</lib/x86_64-linux-gnu/libc-2.15.so>) = 0
1390219298.394297 mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x2aaaaaae9000
1390219298.394694 mmap(NULL, 7220736, PROT_READ, MAP_PRIVATE, 3</usr/lib/locale/locale-archive>, 0) = 0x2aaaab090000
1390219310.741164 mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x2aaaaaaea000
"""
MMAP_CALLS = set("mmap".split())


# TODO: add network tracing support
# we like things to be local, but sometimes things are fetched from the
# network we would need to track:
# - socket call that returns a socket desc as res
# - connect call that links a socket # with an IP address
#    based on port eventually ignoring some ops such as DNS on port 53
# - from then on regular read/write calls are done on the socket desc
"""
1390574084.074347 socket(PF_INET, SOCK_STREAM, IPPROTO_IP) = 3
1390574084.074408 connect(3, {sa_family=AF_INET, sin_port=htons(80), sin_addr=inet_addr("173.236.164.135")}, 16) = 0
1390574084.144240 select(4, NULL, [3<socket:[28508374]>], NULL, {900, 0}) = 1 (out [3], left {899, 999995})
1390574084.144572 write(3<socket:[28508374]>, "G"..., 108) = 108
1390574084.145038 select(4, [3<socket:[28508374]>], NULL, NULL, {900, 0}) = 1 (in [3], left {899, 929620})
1390574084.215694 recvfrom(3, "H"..., 511, MSG_PEEK, NULL, NULL) = 492
1390574084.215977 read(3<socket:[28508374]>, "H"..., 264) = 264
1390574084.216536 stat("index.html", 0x7fffefb111e0) = -1 ENOENT (No such file or directory)
1390574084.216840 select(4, [3<socket:[28508374]>], NULL, NULL, {900, 0}) = 1 (in [3], left {899, 999995})
1390574084.217017 read(3<socket:[28508374]>, "<"..., 228) = 228
"""
NETWORK_CALLS = set("connect socket recv recvfrom recvmsg".split())


def parse_line(line, process, settings):
    """
    Parse a line and update the process. Return None or a new forked child.
    Handle lines in the format:
        tstamp            func(args) = result
        1388237979.978603 read(6<pipe:[8050018]>, "+", 1) = 1
    All the logic for handling syscall is in this function
    """
    if not line:
        return

    ln = line.strip()
    if not ln:
        return

    collect_stats = settings.stats
    # NB: unfinished business should not exist based on the traced syscalls and
    # the per process tracing there are rare cases (e.g. a strace of an strace
    # build) where these may show up BUT are not from strace proper (rather
    # they show in the strace code) assert '<unfinished' not in line and
    # 'resumed>' not in line, '<unfinished or resumed> found: cannot continue'

    # ignore some lines
    if has_error(ln, settings.errors):
        if collect_stats:
            process.failed_syscalls_count += 1
        return

    proc_pid = process.pid

    # parse a entry and arguments
    e = parse_entry(ln)
    if not e:
        # ignore all lines that are not parsing cleanly
        # such as not ending with a clean return code
        if collect_stats:
            process.line_parsing_errors_count += 1
        logger.error("parse_line: Unable to parse pid: %(proc_pid)r, " "line: %(line)r" % locals())
        return

    # decode, normalize and resolve paths and descriptors
    warn = resolve_descriptors(e, True)
    if warn:
        if collect_stats:
            process.descriptor_warnings_count += 1
        logger.warning(
            "parse_line: Unable to decode descriptor for pid: "
            "%(proc_pid)r, line: %(line)r" % locals()
        )

    # resolve descriptors must have happened before
    resolve_paths(e, process.cwd if hasattr(process, "cwd") else None)

    if collect_stats:
        process.per_syscall_counts[e.func] += 1

    # process a line according to its syscall function
    # NB: this could have been a dict of func-> function to call,
    # but an elif cascade is simpler and works best with several similar
    # syscalls

    # TODO: check result/return code!!!!
    # mmap related calls return hex
    # most call return ints

    if e.func in CHANGE_DIR_CALLS:
        # we set a new cwd for the caller to use
        # arg0 is the path
        new_cwd = e.args[0]
        # is this a really good new absolute cwd? do not use that cwd if not
        if posixpath.isabs(new_cwd):
            process.cwd = new_cwd

    elif e.func in (NEW_PROCESS_CALLS | CLONE_CALLS):
        # handle forks of child processes
        pid = int(e.result)
        process.children[pid] = e.tstamp
        last_exec = None
        if e.func in CLONE_CALLS:
            # clones inherit from the last exec of their parent
            # while forks set their execs themselves
            if process.execs:
                last_exec = process.execs[-1]
            else:
                last_exec = Exec(command="UNKNOWN", args="", tstamp=e.tstamp)
        child = Process(
            pid=pid, ppid=process.pid, cwd=process.cwd, init_exec=last_exec, tstamp=e.tstamp
        )
        # logger.debug('parse_line: new process: %(child)r.' % locals())
        return child

    elif e.func in EXEC_CALLS:
        # arg0 is the command and arg[1:] command args
        exe = Exec(command=e.args[0], args=e.args[1:], tstamp=e.tstamp)
        # logger.debug('parse_line: new exe: %(exe)r.' % locals())
        process.execs.append(exe)
        # logger.debug('parse_line: new exe process: %(process)r.' % locals())

    elif e.func in READ_CALLS:
        # arg0 is the path
        process.add_read(e.args[0], e.tstamp, settings.ignored_reads)

    elif e.func in WRITE_CALLS:
        # arg0 is the path
        process.add_write(e.args[0], e.tstamp, settings.ignored_writes)

    elif e.func in READ_WRITE_CALLS:
        # arg0 is the src path, arg1 the target path
        process.add_readwrite(
            e.args[0],
            e.args[1],
            e.tstamp,
            e.tstamp,
            settings.ignored_reads,
            settings.ignored_writes,
        )

    elif e.func in (OPEN_CALL, OPENAT_CALL):
        # OPEN_CALL: arg0 is the path arg1 are the flags

        # OPENAT_CALL: arg0 is the basedir
        # arg1 is the path (should be resolved, so ignore basedir)
        # after path resolution, the path is in arg0, and flags in arg1
        # arg2 are the flags, like for open
        opth = e.args[0]
        oflags = open_flags(e.args[1])

        if has_read_flag(oflags):
            # TODO: for now we pass, so we could track this too ....
            # process.add_read(e.args[0], e.tstamp, settings.ignored_reads)
            pass
        if has_write_flag(oflags):
            process.add_write(opth, e.tstamp, settings.ignored_writes)

    else:
        # TODO: log or raise exception if we have an unknown syscall
        if collect_stats:
            process.unhandled_syscalls.add(e.func)


def open_flags(s):
    """
    Return a list of flags decoded from a string
    """
    return [f.strip() for f in s.split("|") if f]


def _has_flag(flags, open_flags):
    return any(f in open_flags for f in flags) and not any(f in OPEN_DIR_FLAGS for f in flags)


def has_read_flag(flags):
    return _has_flag(flags, OPEN_READ_FLAGS)


def has_write_flag(flags):
    return _has_flag(flags, OPEN_WRITE_FLAGS)


def memoize(fun):
    """
    Decorate fun function args and cache return values. Arguments must be
    hashable. kwargs are not handled. Used to speed up some often executed
    functions.
    """
    memos = {}

    @functools.wraps(fun)
    def memoized(*args):
        args = tuple(tuple(arg) if isinstance(arg, list) else arg for arg in args)
        try:
            return memos[args]
        except KeyError:
            memos[args] = fun(*args)
            return memos[args]

    return functools.update_wrapper(memoized, fun)


@memoize
def erre(errors):
    return [re.compile(e).match for e in errors]


def has_error(l, errors):
    """Return True if the line is an error line"""
    return any(er(l) for er in erre(errors))


@memoize
def includes_excludes(fileset):
    """Return set of includes and sets of excludes for a fileset"""
    includes = set(pat for pat in fileset if pat and not pat.startswith(MINUS))

    excludes = set(pat[1:].strip() for pat in fileset if pat and pat.startswith(MINUS) and pat[1:])
    return includes, excludes


MINUS = "-"


def in_fileset(path, fileset):
    """
    Return True if path is included in AND not excluded from fileset. fileset
    is a list of glob patterns containing plain file paths to match exactly or
    glob patterns as defined in POSIX fnmatch. A list entry is optionally
    prefixed with an minus sign "-" to express an exclusion.

    The order of the fileset items does not matter. If fileset is empty, return
    True. If the path is empty, return False.

    The default for a glob is to match inclusive unless prefixed with -. Glob
    patterns prefixed with - are exclusions. Exclusion patterns have precedence
    over inclusion. This allow to express complex file sets compactly. For
    instance with these patterns all files in /nexb/src/ match UNLESS they end
    with  .so or .o::
        sources = ['/nexb/src/*','-/nexb/src/*.so', '-/nexb/src/*.o']
    """
    if not path:
        return False
    if not fileset:
        return True

    try:
        inclusions, exclusions = includes_excludes(fileset)
        included = path in inclusions or any(fnmatch.fnmatch(path, pat) for pat in inclusions)

        excluded = path in exclusions or any(fnmatch.fnmatch(path, pat) for pat in exclusions)

    except Exception:
        fs = list(fileset)[:5]
        logger.error("in_fileset: path: %(path)r fileset: %(fs)r..." % locals())
        raise
    logger.debug(
        "in_fileset: path: %(path)r is included:%(included)r and "
        "excluded:%(excluded)r." % locals()
    )
    return included and not excluded


PIPE = "pipe:["
SOCKET = "socket:["
PIPE_OR_SOCKET = (
    PIPE,
    SOCKET,
)


def is_special(path):
    """
    Return True if the path is a special path, e.g. pipe or socket descriptor.
    """
    return path and path.startswith(PIPE_OR_SOCKET)


def is_pipe(path):
    """
    Return True if the path is a pipe descriptor.
    """
    return path and path.startswith(PIPE)


def is_ignored_path(path, ignored):
    """
    Return True if a path should be ignored. Ignored is a fileset / list of
    patterns to ignore.
    Special files (such as pipes or sockets) are ignorable too.
    """
    if ignored:
        return in_fileset(path, ignored)
    else:
        return False


def is_ignored_rw_path(readwrite, ignored_reads, ignored_writes):
    """
    Return True if a source to target Readwrite should be ignored based on
    ignored_reads and ignored_writes.
    """
    if is_ignored_path(readwrite.source, ignored_reads) or is_ignored_path(
        readwrite.target, ignored_writes
    ):
        return True
    else:
        return False


def is_ignored_command(executable, ignored_execs):
    """
    Return True if the executable command is an ignored exec.
    """
    if is_ignored_path(executable.command, ignored_execs):
        return True
    else:
        return False


Entry = collections.namedtuple("Entry", "tstamp result func args")


def parse_entry(ln):
    """
    Return an Entry by parsing a line in the form of:
        tstamp  func(args) = result
    The Entry args is a list of decoded args.
    """
    try:
        line = ln.strip()
        # ignore lines with +++ and similar signal related trace
        if "=" not in line or " " not in line:
            return
        # first split on space the time stamp from the right side
        tstamp, line = line.split(" ", 1)
        # then split the return code with =
        line, result = line.rsplit("=", 1)
        result = result.strip()
        line = line.strip()
        # find the syscall function with a ( split
        func, line = line.split("(", 1)
        args = line.strip().rstrip(")")
        # at this stage we have :
        # tstamp, result, func, args
        # the meaning of args and result code is function-dependent
        return Entry(tstamp, result, func, decode_args(args))
    except ValueError as e:
        logger.error("In parse_entry: Ignored parsing error" " for line: %(ln)r: %(e)r" % locals())


# catch things like , [/* 65 vars */]
VARS_COMMENT = re.compile(r", \[\/\* \d+ vars \*\/\]")


# catch things like '4</lib/x86_64-linux,-gnu/libtinfo.so.5.9>, '
# and close(6<pipe:[82592441]>)
file_descriptors = re.compile(
    # first form: single FD in () : '(4</lib/x86_64-linux>)'
    # second form: FD at the beginning of args: '(4</lib/x86_64-linux>, '
    # third form: FD in the middle of args: ', 4</lib/x86_64-linux>, '
    # fourth form: FD at the end of args: ', 4</lib/x86_64-linux>)'
    # alternation as a non capturing group for start markers(all forms)
    r"""(?:^|, )"""
    # this only capturing group is the FD
    r"""("""
    # digits then opening bracket
    r"""\d+<"""
    # file descriptors always start with one of: / pipe: or socket:
    # as a non capturing group
    r"""(?:\/|socket\:|pipe\:)"""
    # anything except <>"' and \
    r"""[^\<\>\'\"\\]*"""
    # closing bracket
    r""">"""
    r""")"""
    # alternation as a non capturing group for end markers (all forms)
    r"""(?:, |$)"""
).findall


def decode_args(args):
    """
    Return a list of arguments from args string.

    Based on a strace output like::
        execve("/bin/bash", ["/bin/bash", "-c", "gcc -Wall -Wwrite-strings -g -O2   -o strace bjm.o ."...], [/* 24 vars */]) = 0
    The expected args string is something like this::
        "/bin/bash", ["/bin/bash", "-c", "gcc -Wall -Wwrite-strings -g -O2   -o strace bjm.o ."...], [/* 24 vars */]
    And the returned list looks like this::
        ['/bin/bash', '/bin/bash', '-c', 'gcc -Wall -Wwrite-strings -g -O2   -o strace bjm.o ....']

    Note: we use shlex but it has limitations.... A structured trace output
    may help in the future.
    """
    try:
        # First some cleanup on args
        # remove var comments
        cleaned = re.sub(VARS_COMMENT, "", args)

        # remove deleted info: this can happen in decoded file descriptors
        # read(0</tmp/sh-thd-1391680596 (deleted)>, "..."..., 61) = 61
        cleaned = cleaned.replace(" (deleted)>", ">")

        # quote file descriptors in the form '4<....>, ' so they are shlexed
        # as one arg if they have spaces of commas
        for desc in file_descriptors(cleaned):
            cleaned = cleaned.replace(desc, '"%(desc)s"' % locals())

        # Then lex
        lexed = shlex.shlex(cleaned, posix=True)
        lexed.commenters = ""
        # use comma and whitespace as args delimiters
        lexed.whitespace_split = True
        lexed.whitespace = ","
        decoded = list(lexed)

        # Then fix brackets: [ at beginning and ] at end of each arg
        # FIXME: should do it only on the first and last arg but not all args
        # NOTE: striping the spaces is needed: this is a a side effect of
        # using shlex
        fixed = [a.strip().lstrip("[").rstrip("]").strip() for a in decoded]
    except ValueError as e:
        raise ValueError("Error while decoding args: %(args)s" % locals())
    return fixed


# map of a syscall to a list of 0-based positions of args
# that are descriptors and need decoding
FDESC_ARGS = {
    "renameat": [0, 2],
    "linkat": [0, 2],
    "symlinkat": [1],
    "dup2": [0, 1],
    "dup3": [0, 1],
}

# Add set of syscalls functions having a file descriptor as first argument
for fu in set("fchdir dup connect openat recv recvfrom recvmsg".split()) | READ_CALLS | WRITE_CALLS:
    FDESC_ARGS[fu] = [0]


def resolve_descriptors(entry, check_num=False):
    """
    Resolve/Decode file descriptors paths of an entry as needed.
    """
    warn = False
    try:
        for pos in FDESC_ARGS[entry.func]:
            if check_num and entry.args[pos].isdigit():
                warn = True
            desc = decode_descriptor(entry.args[pos])
            entry.args[pos] = desc
    except KeyError:
        pass
    return warn


descriptor = re.compile(r"^" r"(?P<fd_num>\d+)" r"<" r"(?P<path>.*)" r">$").match


@memoize
def decode_descriptor(s):
    """
    Return path string if s is a file, pipe or socket descriptor or s
    otherwise.

    Descriptors are encoded like this by strace:
      4</lib/x86_64-linux-gnu/libtinfo.so.5.9>
    In this case, we return this path:
        /lib/x86_64-linux-gnu/libtinfo.so.5.9
    """
    desc = descriptor(s)
    if desc and desc.group("path") and is_special(desc.group("path")):
        # handle keeping the file desc to the pipe or socket ID
        # fixme: we should likely track pipes in more details
        pass
    return desc.group("path") if desc else s


# map of a func to a list of 0-based positions of args that are paths and need
# resolution relative to CWD
# NB: fdesc are always absolute and should not need normalization
PATH_ARGS = {
    "chdir": [0],
    "rename": [0, 1],
    "link": [0, 1],
    "symlink": [0, 1],
    "truncate": [0],
    "open": [0],
    "execve": [0],
    "symlinkat": [0],
}


# map of "at" functions that use a dir FD to resolve path instead of CWD the
# value is a list of tuples where the 1st member is the dir to use for
# resolution and the second member is the path to resolve against that dir.
# Resolution should take if and only if the path is relative and not absolute.
AT_CALLS_PATH_ARGS = {
    # linkat and renameat [0] and [2] are relative dirs for [1] and [3]. The
    # order from bigger index to smaller index is important to avoid messing
    # up the  positions when we delete the dir position once resolution is
    # completed!!
    "renameat": [(2, 3), (0, 1)],
    "linkat": [(2, 3), (0, 1)],
    # only the target of a symlinkat can be relative [2] is rel to [1]
    "symlinkat": [(1, 2)],
    # in general [0] is AT_FCWD but this is not guaranteed: [1] is el to [0]
    "openat": [(0, 1)],
}


def resolve_paths(entry, cwd):
    """
    Resolve the paths of an entry if needed for calls that have a known.

    Normalize multipath at calls args positions.
    For these entry agrs where "at" calls paths are normalized such that:
    - the source is arg[0] and the target is arg[1] for multipath calls
    - the path is arg[0] for single paths calls
    Some calls such as openat, linkat, symlinkat, renameat use multiple paths
    and file descriptors to represent one path, in general a base directory
    FD and a path relative to that directory.
    """
    # replace any special AT_FDCWD arg value with the cwd value
    for idx, arg in enumerate(entry.args):
        entry.args[idx] = cwd if arg == "AT_FDCWD" else arg

    # resolve paths for calls that only use CWD
    if entry.func in PATH_ARGS:
        positions = PATH_ARGS[entry.func]
        for pos in positions:
            entry.args[pos] = norm_path(entry.args[pos], cwd)

    # resolve paths for calls that use a FD dir path instead of CWD
    if entry.func in AT_CALLS_PATH_ARGS:
        positions = AT_CALLS_PATH_ARGS[entry.func]
        for base_dir_pos, rel_path_pos in positions:
            base_dir = entry.args[base_dir_pos]
            if not base_dir:
                base_dir = cwd
            # save the new resolved path
            normed_path = norm_path(entry.args[rel_path_pos], base_dir)
            # remove the right pos, which is the old relative path
            del entry.args[rel_path_pos]
            # replace the left pos with the new saved resolved path
            entry.args[base_dir_pos] = normed_path
    return entry


def normalize_at_calls_args(entry):
    """
    This function ensures that the only one resolved path exists in these
    cases.
    """
    if not entry.func in AT_CALLS_PATH_ARGS:
        return entry


def norm_path(path, cwd):
    """
    Normalize a path using a cwd if needed and possible.
    """
    if not posixpath.isabs(path):
        has_abs_cwd = cwd and posixpath.isabs(cwd)
        if has_abs_cwd:
            if not posixpath.isabs(path):
                path = posixpath.join(cwd, path)
        else:
            logger.info(
                "In norm_path: Unable to resolve path: "
                "%(path)s: cwd %(cwd)r is invalid." % locals()
            )
    return posixpath.normpath(path)


# An exec is loaded in a process: we keep the command, args and time stamp
Exec = collections.namedtuple("Exec", "command args tstamp")

# An atomic rename or copy-like operation with a src and target paths
Readwrite = collections.namedtuple("Readwrite", "source target start_tstamp end_tstamp")

# An operation, where a command in a process read sources and writes targets
# at some time stamps
Operation = collections.namedtuple(
    "Operation", "pid command sources targets start_tstamp end_tstamp"
)

Operation.to_dict = Operation._asdict


class Process(object):
    """
    Process object. Hold lists of file reads/writes/readwrites, list of execs
    and list of forked children.
    """

    def __init__(self, pid, ppid, cwd, init_exec=None, tstamp=0):
        # process id and parentd pid
        self.pid = pid
        self.ppid = ppid

        self.cwd = cwd
        self.tstamp = tstamp

        # execs is a list of Execs tuples
        if init_exec:
            # set initial exec for clones:
            # they inherit the current exec from their parent process
            self.execs = [init_exec]
        else:
            self.execs = []

        # a map of unique paths to the first tstamp
        self.reads = {}
        # a map of unique paths to the last tstamp
        self.writes = {}
        # a list of atomic Readwrite tuples (from cp-like commands, rename
        # syscalls or fd duplicates)
        self.readwrites = []

        # a map of Process id to tstamps
        self.children = {}

        # stats accumulators
        self.failed_syscalls_count = 0
        self.line_parsing_errors_count = 0
        self.descriptor_warnings_count = 0
        self.per_syscall_counts = collections.defaultdict(int)
        self.unhandled_syscalls = set()

    def __attrs(self):
        return (
            self.pid,
            self.ppid,
            self.cwd,
            self.tstamp,
            self.execs,
            self.reads,
            self.writes,
            self.readwrites,
            self.children,
        )

    def __eq__(self, other):
        return isinstance(other, Process) and self.__attrs() == other.__attrs()

    def __hash__(self):
        return hash(self.__attrs())

    def __str__(self):
        return "Process(pid=%(pid)r, ppid=%(ppid)r, " "execs=%(execs)r)" % self.__dict__

    __repr__ = __str__

    def as_sorted_paths(self, mapping):
        """
        Return list of paths from a mapping path->tstamp sorted by tstamp.
        """
        srt = sorted(
            (
                v,
                k,
            )
            for k, v in mapping.items()
        )
        return [v for _k, v in srt]

    def pformat(self):
        """
        Return a formatted string representation of a process. Used mostly for
        testing and debugging.
        """
        pid = self.pid
        ppid = self.ppid
        tstamp = self.tstamp
        execs = ", ".join(c.command for c in self.execs)

        indent = "  "
        reads = "\n".join(indent + f for f in self.as_sorted_paths(self.reads))
        writes = "\n".join(indent + f for f in self.as_sorted_paths(self.writes))
        readwrites = "\n".join(
            indent
            + repr(
                (
                    r.source,
                    r.target,
                )
            )
            for r in self.readwrites
        )
        children = "\n".join(indent + str(f) for f in self.as_sorted_paths(self.children))
        rep = (
            """Process: pid=%(pid)r, ppid=%(ppid)r, execs=%(execs)r, tstamp=%(tstamp)s:
 Reads:
%(reads)s
 Writes:
%(writes)s
 Read/Writes:
%(readwrites)s
 Children:
%(children)s
"""
            % locals()
        )

        return "\n".join(l.rstrip() for l in rep.splitlines() if l.rstrip())

    def remove_read_if_write(self):
        """Remove a read from reads if it exists in the writes."""
        for path in list(self.reads.keys()):
            if path in self.writes:
                del self.reads[path]
        return self

    def add_read(self, path, tstamp, ignored_reads):
        """Add a new read."""
        if not is_ignored_path(path, ignored_reads):
            # this keeps the time stamp to the first read time
            if path not in self.reads:
                self.reads[path] = tstamp
        return self

    def add_write(self, path, tstamp, ignored_writes):
        """Add a new write."""
        if not is_ignored_path(path, ignored_writes):
            # this updates the time stamp to the last write time
            self.writes[path] = tstamp
        return self

    def add_readwrite(
        self, source, target, start_tstamp, end_tstamp, ignored_reads, ignored_writes
    ):
        """
        Add a new readwrite, ignoring it if the read or write is ignored.
        """
        # ignore readwrite where source is target
        if source != target:
            rw = Readwrite(source, target, start_tstamp, end_tstamp)
            if not is_ignored_rw_path(rw, ignored_reads, ignored_writes):
                self.readwrites.append(rw)
        return self

    def filter(self, ignored_reads, ignored_writes, ignored_execs):
        """
        Apply ignored reads, writes and execs filters to self.
        """
        ignored_reads = ignored_reads or []
        if ignored_reads:
            for path in dict(self.reads):
                if is_ignored_path(path, ignored_reads):
                    del self.reads[path]

        ignored_writes = ignored_writes or []
        if ignored_writes:
            for path in dict(self.writes):
                if is_ignored_path(path, ignored_writes):
                    del self.writes[path]

        if ignored_reads or ignored_writes:
            self.readwrites = [
                rw
                for rw in self.readwrites
                if not is_ignored_rw_path(rw, ignored_reads, ignored_writes)
            ]

        # filter out RW to the same file
        self.readwrites = [rw for rw in self.readwrites if rw.source != rw.target]

        # filter out processes that use ignored exec commands
        # We simply wipe out any reads and writes: the process will
        # therefore become empty unless it has children
        ignored_execs = ignored_execs or []
        if ignored_execs:
            if any(is_ignored_command(ex, ignored_execs) for ex in self.execs):
                # reset rw for ignored commands
                self.reads = {}
                self.writes = {}
                self.readwrites = []

        return self

    def is_empty(self):
        """
        Return True if all lists are empty. This type of processes does nothing
        file-wise and is a candidate for removal.
        """
        return not any(
            (
                self.reads,
                self.writes,
                self.readwrites,
                self.children,
            )
        )

    def is_pure_forker(self):
        """
        Return True if all lists except children are empty. This type of
        processes does nothing but forking. It is a candidate for shunting,
        e.g. moving execs and children up to parent and removal for
        simplification.
        """
        return self.children and not any(
            (
                self.reads,
                self.writes,
                self.readwrites,
            )
        )

    def is_multiplexed(self, multiplexers):
        """
        Return True if the process does multiplexed operations.
        """
        commands = [x.command for x in self.execs]
        return is_multiplexed(commands, multiplexers)

    def demux(self, multiplexers):
        """
        Fix the reads/writes if we have a multiplexer exec.
        """
        rds, wrts = self.reads, self.writes
        if self.execs:
            cmds = [x.command for x in self.execs]
        else:
            cmds = []
        self.reads, self.writes, rw = demux(rds, wrts, cmds, multiplexers)
        self.readwrites.extend(rw)
        return self

    def clean(self, settings):
        """
        Apply multiple cleaning and filtering steps to self and return self.
        """
        self.remove_read_if_write()
        if settings:
            self.demux(settings.multiplexers)
            self.filter(settings.ignored_reads, settings.ignored_writes, settings.ignored_execs)
        return self

    def dump(self, output_dir):
        """
        Save serialized self to output_dir and return saved file path.
        """
        out_file = Process.get_file(output_dir, self.pid)
        with open(out_file, "wb") as of:
            pickle.dump(self, of, protocol=0)
        return out_file

    def erase(self, output_dir):
        """
        Erase serialized self from output_dir and return self.
        """
        out_file = Process.get_file(output_dir, self.pid)
        os.remove(out_file)
        return self

    @staticmethod
    def load(input_dir, pid):
        """
        Return a new Process built from a serialized file in input_dir.
        """
        in_file = Process.get_file(input_dir, pid)
        assert os.path.exists(in_file)
        with open(in_file, "rb") as inf:
            return pickle.load(inf)

    @staticmethod
    def get_file(fdir, pid):
        pid = str(pid)
        return os.path.join(fdir, pid + ".pickle")

    def reads_paths(self, ignore_pipes=True):
        """
        Return a set of paths being read.
        """
        reads = set(rw.source for rw in self.readwrites)
        reads.update(self.reads)
        return self.filter_pipes(reads, ignore_pipes)

    def filter_pipes(self, paths_set, ignore_pipes=True):
        if ignore_pipes:
            return set(p for p in paths_set if not is_pipe(p))
        else:
            return paths_set

    def writes_paths(self, ignore_pipes=True):
        """
        Return a set of paths being written.
        """
        writes = set(rw.target for rw in self.readwrites)
        writes.update(self.writes)
        return self.filter_pipes(writes, ignore_pipes)

    def as_ops(self):
        """Yield operations."""
        if self.is_empty():
            yield None

        if self.execs:
            command = ", ".join(e.command for e in self.execs)
        else:
            command = "UNKNOWN"
        pid = self.pid
        for source, target, sts, ets in self.readwrites:
            yield Operation(pid, command, [source], [target], sts, ets)

        # get proper ts for reads and writes
        # TODO: we should track & use time intervals rather than just stamps
        ts = sorted(list(self.reads.values()) + list(self.writes.values()))
        if ts:
            first_ts = min(ts)
            last_ts = max(ts)
        elif self.execs:
            first_ts = self.execs[0].tstamp
            last_ts = self.execs[-1].tstamp
        else:
            logger.error("as_ops: %(pid)r has incorrect timestamp" % locals())
            first_ts = "0"
            last_ts = "0"

        yield Operation(
            pid, command, list(self.reads.keys()), list(self.writes.keys()), first_ts, last_ts
        )


def is_multiplexed(commands, multiplexers):
    """
    Return True if any command in the commands list is a multiplexing command.

    Some commands such as cp and javac can read several files at once and
    write several files in one process step. In these case each read is
    related to one write, and not all reads related to all writes. However
    these operations are independent and should be treated the same as
    multiple atomic read/writes. When we see such command, we can demux the
    reads and writes to get distinct operations , such as:

      read a -> write a, read b -> write b
    ...instead of an interleaved/cluttered/multiplexed:
      read a and b -> write a and b

    """
    if not multiplexers:
        return False
    for c in commands:
        for i in multiplexers:
            if fnmatch.fnmatch(c, i):
                return True
    return False


# TODO: javac by default multiplexes a lot: typically a whole directory
# tree of java files is compiled by one process in many class files this
# means that all traced reads will be connected to all writes i.e foo.java
# and bar.java will both be connected in one operation to foo.class and
# bar.class we need to demux this based on java compiler conventions with
# caveats: bar.java may compile alone to bar$inner.class and baz.class as
# multiple classes can be contained in one source file Also non-java but
# jvm-based languages can compile to class files with other unrelated
# conventions such as Groovy, Clojure and Scala finally there are several
# other common java compilers beyond oracle and the openjdk, the most
# prominent one being the Eclipse jdt that may come with yet more devilish
# details

# TODO: handle interpreted languages-based tools such as Scons, rake,
# buildout: these may present some challenges as a single coarsed grained
# process may perform a large number of multiplexed operations
#
# One approach could be to use a timeline-based demuxing, tracing open/closing
# of files


def demux(reads, writes, commands, multiplexers):
    return path_demux(reads, writes, commands, multiplexers)


def path_demux(reads, writes, commands, multiplexers):
    """
    Return new updated reads, writes and readwrites if we have a multiplexer
    command.
    """
    reads, writes = dict(reads), dict(writes)
    readwrites = []

    if not is_multiplexed(commands, multiplexers):
        return reads, writes, readwrites

    # operation involving a single read and single write do not need demux
    if len(reads) == len(writes) == 1:
        return reads, writes, readwrites

    matched_paths = match_paths(reads.keys(), writes.keys())

    reads_to_del = set()
    writes_to_del = set()
    for read, write in matched_paths:
        rts = reads[read]
        wts = writes[write]
        readwrites.append(Readwrite(read, write, rts, wts))
        reads_to_del.add(read)
        writes_to_del.add(write)

    for r in reads_to_del:
        del reads[r]
    for w in writes_to_del:
        del writes[w]

    return reads, writes, sorted(readwrites)


def match_paths(paths1, paths2):
    """
    Given two sequences of paths, match every paths in paths1 with paths in
    paths2 using a common suffix. Yield a sequences of the top match tuples
    (p1, p2,)
    """
    from collections import defaultdict

    for p1 in paths1:
        cp1 = defaultdict(set)

        for p2 in paths2:
            cmn, lgth = pathutils.common_path_suffix(p1, p2)
            if cmn:
                cp1[lgth].add(p2)

        if cp1:
            tops = cp1[max(cp1)]
            # do not keep multiple matches of len 1: these are filename matches
            # and are too weak to be valid in most cases
            if not (max(cp1) == 1 and len(tops) > 1):
                for top in tops:
                    yield p1, top


def cleaner(to_clean, input_dir, output_dir=None, settings=None):
    """
    Clean a process list or input dir, applying settings filters and removing
    empty processes. Return the cleaned list. Input is an optional list of
    processes OR an optional list of processes pid and input_dir containing
    parsed pickled Process objects. Execute as many "cleaning" cycles as
    necessary until no more empties are found. Write output to output_dir or
    overwrites input_dir content if input_dir is present and output_dir is
    None.
    """

    save_dir = output_dir or input_dir
    logger.info("Filtering and saving cleaned traces to %(save_dir)r." % locals())
    start = time.time()

    combo_msg = (
        "cleaner: Invalid combination of to_clean: %(to_clean)r and " "input_dir:%(input_dir)r."
    )
    assert to_clean or (to_clean and input_dir) or (not to_clean and input_dir), (
        combo_msg % locals()
    )

    if not to_clean:
        # if we have an output dir and nothing yet to clean then build the list
        # of pids to clean
        to_clean = get_stored_pids(input_dir)

    if input_dir:
        # re-hydrate process objects if we have only pids
        to_clean = load(input_dir, to_clean)

    start_len = len(to_clean)

    # first re-apply filters
    for proc in to_clean:
        proc.clean(settings)
    duration = time.time() - start
    logger.info(
        ("Applied filters to %(start_len)r traces in " "%(duration).2f seconds.") % locals()
    )

    # then execute as many cleaning cycles as needed
    start = time.time()
    cycles = 0
    while True:
        cycles += 1
        len_before_cleaning = len(to_clean)
        to_clean = remove_empties(to_clean, input_dir, output_dir)
        len_after_cleaning = len(to_clean)
        if len_before_cleaning == len_after_cleaning:
            # stop when cleaning does not reduce the process count anymore
            break

    cleaned_count = start_len - len(to_clean)
    duration = time.time() - start
    logger.info(
        (
            "Filtered %(cleaned_count)r empty traces from %(save_dir)r "
            "with %(cycles)r cycles in %(duration).2f seconds."
        )
        % locals()
    )

    if input_dir:
        return [p.pid for p in to_clean]
    return to_clean


def get_stored_pids(dir_path):
    """
    Return a list of process IDs from parsed traces stored in dir_path.
    """
    stored = []
    for filename in os.listdir(dir_path):
        path = os.path.join(dir_path, filename)
        # check that the we have only files
        clean_msg = "cleaner: %(path)r is not a regular " "file, does not exist or cannot be read."
        assert os.path.isfile(path), clean_msg % locals()

        pid, _ = filename.rsplit(".", 1)
        pid = int(pid.strip())
        stored.append(pid)
    return sorted(stored)


def load(dir_path, proc_pids):
    """
    Return a list of process objects loaded from dir_path for each PID in the
    proc_pids seq.
    """
    return [Process.load(dir_path, pid) for pid in proc_pids]


def load_from_dir(dir_path):
    """
    Return a list of process objects loaded from dir_path.
    """
    logger.info("Loading traces ...")
    proc_pids = get_stored_pids(dir_path)
    return load(dir_path, proc_pids)


def remove_empties(to_clean, input_dir, output_dir=None):
    """
    Return a list of cleansed processes by removing empty processes including
    their references in parents processes. to_clean is a list of Processes.
    Erase empty Processes files from input_dir if input_dir and output_dir is
    None. Otherwise write cleansed processes to output_dir.
    """

    empties = set()
    empties_parents = set()
    cleansed = []

    def del_proc(proc):
        empties.add(proc.pid)
        empties_parents.add(proc.ppid)
        if input_dir and not output_dir:
            # erase proc file
            proc.erase(input_dir)

    # walk in reverse as the last created processes (deeper in the tree)
    # should be checked first to clean bottom up
    for proc in reversed(to_clean):
        if proc.pid in empties_parents:
            # remove refs to empties in parents
            proc.children = dict(
                (
                    pid,
                    ts,
                )
                for pid, ts in proc.children.items()
                if pid not in empties
            )

        if proc.is_empty():
            del_proc(proc)
            continue

        cleansed.append(proc)
        if input_dir or output_dir:
            # write back
            proc.dump(output_dir or input_dir)

    return cleansed


CommandNode = collections.namedtuple(
    "CommandNode", "type pid index command start_tstamp end_tstamp"
)

FileNode = collections.namedtuple("FileNode", "type path")


def as_graph(processes, settings):
    """
    Return a graph from a list of process objects.
    """
    logger.info("Building graph ...")
    from tracecode._vendor.altgraph.Graph import Graph

    graph = Graph()
    ##############################################################################
    # TODO: CRITICAL to avoid cycles in the graph and ensure this is DAG
    # directed acyclic graph: http://en.wikipedia.org/wiki/Directed_acyclic_graph
    # we should take timing into consideration:
    # the first read to a given path can only happen after the last write has been
    # completed, IFF there are writes that precede a given read
    # therefore a path may appear several times in the graph based on the
    # read/writes
    # this applies to actual files, but be may not to pipes or sockets
    ##############################################################################
    for proc in processes:
        if proc.is_empty():
            continue
        # FIXME: handle forks
        # if not settings.forks and proc.is_pure_forker():
        #     continue
        for i, op in enumerate(proc.as_ops()):
            if not op:
                continue
            # add command Nodes
            # we create a unique node for each unique operation in a process
            cid = "%(command)s %(pid)d, %(start_tstamp)s:%(end_tstamp)s" % op._asdict()
            # pad id with a unique index to ensure each op is unique
            cid = cid + ("-%d" % i)
            co = CommandNode("c", op.pid, i, op.command, op.start_tstamp, op.end_tstamp)
            graph.add_node(cid, co)
            # add file nodes and edges between commands and files
            for pth in op.sources:
                graph.add_node(pth, FileNode("f", pth))
                graph.add_edge(pth, cid, "read", create_nodes=False)
            for pth in op.targets:
                graph.add_node(pth, FileNode("f", pth))
                graph.add_edge(cid, pth, "write", create_nodes=False)
    return graph


def as_file_graph(processes, settings):
    """
    Return a files-only graph from a list of process objects. The graph
    connects files with an edge representing a read-from, write-to operation.
    """
    logger.info("Building graph ..")
    from tracecode._vendor.altgraph.Graph import Graph

    graph = Graph()
    for proc in processes:
        if proc.is_empty() or proc.is_pure_forker():
            # these do no file operations
            continue
        for op in proc.as_ops():
            if not op:
                continue
            # add file nodes and edges between files
            for src in op.sources:
                graph.add_node(src)
                for tgt in op.targets:
                    graph.add_node(tgt)
                    graph.add_edge(src, tgt)
    return graph


def file_sets(graph, settings):
    """
    Return sets of sources, targets and intermediate paths given a file graph and settings.
    """

    logger.info("Building paths index ..")
    sources = set(settings.sources)
    targets = set(settings.targets)

    source_paths = set()
    target_paths = set()
    intermediate_paths = set()

    for pth in graph.node_list():
        if pth in sources:
            if pth in target_paths:
                raise Exception(
                    "Invalid graph and filesets: " "%s is both a source and target" % pth
                )
            else:
                source_paths.add(pth)
        elif pth in targets:
            if pth in source_paths:
                raise Exception(
                    "Invalid graph and filesets: " "%s is both a source and target" % pth
                )
            else:
                target_paths.add(pth)
        else:
            intermediate_paths.add(pth)
    return source_paths, target_paths, intermediate_paths


def analyze_file_graph(procs, settings):
    """
    TODO: Used only in tests
    """
    graph = as_file_graph(procs, settings)
    sources, targets, _interm = file_sets(graph, settings)
    for tgt in targets:
        logger.info("Analyzing target: %(tgt)s ..." % locals())
        subgraph = graph.back_bfs_subgraph(tgt)
        subnodes = set(subgraph.node_list())
        for src in subnodes.intersection(sources):
            yield src, tgt


def node_sets(graph, settings):
    """
    Return sets of sources, targets and intermediate filenodes given a graph
    and settings.
    """
    logger.info("Building paths index ..")
    sources = set(settings.sources)
    targets = set(settings.targets)

    source_nodes = set()
    target_nodes = set()
    intermediate_nodes = set()

    for node in graph:
        file_data = graph.node_data(node)
        if not isinstance(file_data, FileNode):
            continue
        pth = file_data.path
        if pth in sources:
            if node in target_nodes or node in intermediate_nodes:
                raise Exception(
                    "Invalid graph and filesets: "
                    "%s cannot be source, target "
                    "and intermediate." % pth
                )
            else:
                source_nodes.add(node)
        elif pth in targets:
            if node in source_nodes or node in intermediate_nodes:
                raise Exception(
                    "Invalid graph and filesets: "
                    "%s cannot be source, target "
                    "and intermediate." % pth
                )
            else:
                target_nodes.add(node)
        else:
            intermediate_nodes.add(node)
    return source_nodes, target_nodes, intermediate_nodes


def analyze_full_graph(procs, settings, _invert=None):
    """
    Yield tuples (source, target) for every graph source path that is
    connected to a target path. This walks the graph forward or backward based
    on the largest number of sources or targets.

    If _invert is not None and True, then walks the graph in the opposite
    direction than what was decided (used for testing).
    """
    graph = as_graph(procs, settings)
    sources, targets, _interm = node_sets(graph, settings)

    # analyze forward or backward based on number of sources and targets
    forward = len(sources) < len(targets)

    # invert walk for testing if needed
    if _invert is not None and _invert:
        forward = not forward

    if forward:
        from_set = sources
        to_set = targets
        navigator = graph.forw_bfs
        logger.info("Analysis will be from sources to targets ...")
    else:
        from_set = targets
        to_set = sources
        navigator = graph.back_bfs
        logger.info("Analysis will be from targets to sources ...")

    for from_node in from_set:
        from_path = graph.node_data(from_node).path
        logger.info("Analyzing: %(from_path)s ..." % locals())
        reachable = set(navigator(from_node))
        reached = reachable.intersection(to_set)
        for to_node in reached:
            to_path = graph.node_data(to_node).path
            if forward:
                yield from_path, to_path
            else:
                yield to_path, from_path


def save_graphic(graph, file_name, file_type="pdf", mode="dot"):
    """
    Save graph graphic rending of type file_type to file_name. Valid types are
    pdf, gif, png, svg  and dot. Rendering to image or pdf formats requires to
    have graphviz installed and in the path.
    """

    if not has_dot():
        logger.error("Please install graphviz from http://graphviz.org/")
        return

    from tracecode._vendor.altgraph import Dot

    # TODO: add a style for commands and nodes
    def node_visitor(node):
        """
        Return a custom style for a node.
        For file nodes: ellipses, with different colors based on devel/source,
        deployed/target and paths (such as sockets, pipes, existing or not) or
        circle for non- existing things like pipes/sockets? for command nodes:
        boxes, with different colors (such as lighter for pure forkers?).
        """
        # return a styles dict based on the node type or an empty dict for the
        # default (ellipse, white)
        return {}

    dot = Dot.Dot(graph, nodevisitor=node_visitor)
    # redirect temp to a real temp to avoid junk file creation
    import tempfile

    dot.temp_dot = os.path.join(tempfile.mkdtemp(), dot.temp_dot)

    # render left to right
    dot.style(rankdir="LR")

    # save as dot or image/pdf

    if file_type == "dot":
        logger.info("Saving dot file ...")
        dot.save_dot(file_name)
        return file_name
    else:
        logger.info("Building and saving graphic file ...")
        dot.save_img(file_name=file_name, file_type=file_type, mode=mode)
        return file_name + "." + file_type


def as_graphic_from_dir(input_dir, file_name, settings, file_type="pdf"):
    """
    Save graphics of a graph built from processes stored in input_dir. Use
    settings targets to create one graphic for the first target only.
    """
    procs = load_from_dir(input_dir)
    return as_graphic_from_procs(procs, file_name, settings, file_type)


def as_graphic_from_procs(procs, file_name, settings, file_type="pdf"):
    """
    Save graphics of a graph built from processes.
    """
    graph = as_graph(procs, settings)
    target = settings.targets[0] if settings.targets else None
    source = settings.sources[0] if settings.sources else None
    logger.info("Building subgraph for %(target)s..." % locals())

    if target:
        graph = graph.back_bfs_subgraph(target)
    if source:
        graph = graph.forw_bfs_subgraph(source)
    return save_graphic(graph, file_name, file_type)


def dump_dir_to_csv(input_dir, file_name, settings):
    """
    Dump processes graph nodes and relationships in PARSED_DIR in a CSV file
    using this format:
     type(C:command,F:file,R:Read,W:Write Relationship),
     node id,
     node label,
     target node id
    """
    processes = load_from_dir(input_dir)
    dump_procs_to_csv(processes, file_name, settings)


def dump_procs_to_csv(processes, file_name, settings):
    """
    Dump graph nodes and relationships in processes in a CSV file using this
    format:
     type(C:command,F:file,R:Read,W:Write Relationship),
     node id,
     node label,
     target node id
    """
    headers = [
        "type",
        "path",
        "opid",
        "command",
        "start",
        "end",
    ]
    import csv

    with open(file_name, "w") as dump_file:
        wrtr = csv.writer(dump_file)
        wrtr.writerow(headers)
        for item in graph_as_tuples(processes, settings):
            wrtr.writerow(item)


def graph_as_tuples(processes, settings):
    """
    Yield graph nodes and relationships in processes as as tuples using this
    format:
     type(C:command,F:file,R:Read,W:Write Relationship),
     node id,
     node label,
     target node id
    """
    files = set()
    logger.info("Dumping graph ...")
    for proc in processes:
        if proc.is_empty():
            continue
        for i, op in enumerate(proc.as_ops()):
            if not op:
                continue
            # dump commands
            # we create a unique node for each unique operation in a process
            opid = str(op.pid) + "." + str(i)
            yield ("c", None, opid, op.command, op.start_tstamp, op.end_tstamp)
            # add file nodes and edges between commands and files
            for pth in op.sources:
                if pth not in files:
                    fn = ("f", pth, None, None, None, None)
                    yield fn
                    files.add(pth)
                # add read edge
                re = ("r", pth, opid, op.command, op.start_tstamp, op.end_tstamp)
                yield re
            for pth in op.targets:
                if pth not in files:
                    fn = ("f", pth, None, None, None, None)
                    yield fn
                    files.add(pth)
                # add write edge
                we = (
                    "w",
                    pth,
                    str(op.pid) + "." + str(i),
                    op.command,
                    op.start_tstamp,
                    op.end_tstamp,
                )
                yield we


def debug_graph_print(input_dir, settings):
    """
    Print a debug list of nodes from a graph focused on sources and targets,
    sorted from sources to targets for one source.
    """
    procs = load_from_dir(input_dir)
    graph = as_graph(procs, settings)
    # keep only the first source and target.....
    source = settings.sources[0] if settings.sources else None
    target = settings.targets[0] if settings.targets else None

    if source:
        graph = graph.forw_bfs_subgraph(source)

    nodes = graph.iterdfs(start=source, end=target, forward=True)
    for node in nodes:
        nd = graph.node_data(node)
        print(node, nd or "")


@memoize
def file_name(path):
    """
    Return a file or dir name based on posix path. Either the file name for a
    file or the directory name for a directory. Recurse to handle paths ending
    with a path separator.
    """
    left, right = posixpath.split(path)
    if right:
        return right
    elif left:
        return file_name(left)
    else:
        return ""


HAS_DOT = None


def has_dot():
    """
    Check that graphviz dot is in the path and available.
    """

    GRAPHVIZ_VERSION = "v2.3.6+"

    global HAS_DOT
    if HAS_DOT is not None:
        return HAS_DOT

    try:
        process = subprocess.Popen(
            "dot -V", stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True
        )
        output, __err = process.communicate()
        retcode = process.poll()
        if not retcode:
            HAS_DOT = True
        else:
            logger.error(
                'Graphviz "dot" executable not found.'
                "Please install Graphviz "
                "%(GRAPHVIZ_VERSION)s." % locals()
            )
            HAS_DOT = False
    except:
        logger.error(
            'Graphviz "dot" executable not found.'
            "Please install Graphviz "
            "%(GRAPHVIZ_VERSION)s." % locals()
        )
        HAS_DOT = False
    return HAS_DOT


def flatten(lists):
    """
    Return an iterable of flattened items from the seqs of lists.
    """
    return itertools.chain(*lists)


def file_lists(procs, debug=False):
    """
    Given a list of processes, return two sets of unique paths being read and
    written. If debug is True, the set contains unique tuples of (path,
    process id) instead.
    """
    logger.info("Building file lists ...")
    if not debug:
        all_reads = set(flatten(p.reads_paths() for p in procs))
        all_writes = set(flatten(p.writes_paths() for p in procs))
    else:
        all_reads = set()
        all_writes = set()
        for p in procs:
            # return tuples of path, pid instead of plain path
            for r in p.reads_paths():
                all_reads.add(
                    (
                        r,
                        str(p.pid),
                    )
                )
            for w in p.writes_paths():
                all_writes.add(
                    (
                        w,
                        str(p.pid),
                    )
                )

    return all_reads, all_writes


def save_file_lists(parsed_dir, reads_file, writes_file, debug=False):
    """
    Given a directory of stored parsed process traces, writes the list of read
    and written paths to reads_files and writes_file.
    """
    procs = load_from_dir(parsed_dir)
    all_reads, all_writes = file_lists(procs, debug)

    if debug:
        all_reads = [" : ".join(x) for x in all_reads]
        all_writes = [" : ".join(x) for x in all_writes]

    logger.info("Saving file lists ...")
    save_sorted(reads_file, all_reads)
    save_sorted(writes_file, all_writes)


def file_rw_counts(procs):
    """
    Given a list of processes, return a map of unique paths being read and
    written. The map key is a path and the value is a tuple of int counting
    the number of times a file was read and written to (only one read or
    write per process is counted).
    """
    logger.info("Building file lists ...")
    from collections import Counter

    reads = Counter()
    writes = Counter()
    for proc in procs:
        reads.update(proc.reads_paths(ignore_pipes=False))
        writes.update(proc.writes_paths(ignore_pipes=False))

    for path, rcnt in reads.items():
        wcnt = 0
        if path in writes:
            wcnt = writes[path]
            del writes[path]
        yield path, rcnt, wcnt

    rcnt = 0
    for path, wcnt in writes.items():
        yield path, rcnt, wcnt


def save_file_lists_with_counts(parsed_dir, inv_file):
    """
    Given a directory of stored parsed process traces, writes the list of read
    and written paths to inv_file with a count of the number of time a file is
    read or written.
    """
    procs = load_from_dir(parsed_dir)
    import csv

    logger.info("Saving file lists ...")
    with open(inv_file, "w") as out_file:
        wrtr = csv.writer(out_file)
        for item in file_rw_counts(procs):
            wrtr.writerow(item)


def save_guessed_sources_and_targets(dir_path, sources_file, targets_file):
    """
    Given a directory of stored parsed process traces, write the list of found
    source and target paths to reads_files and targets_file.
    """
    sources, targets = guess_sources_and_targets_from_dir(dir_path)
    save_sorted(sources_file, sources)
    save_sorted(targets_file, targets)


def save_sorted(file_out, seq):
    """
    Write sorted seq to file_out file, one line per element.
    """
    with open(file_out, "w") as fo:
        fo.write("\n".join(sorted(seq)))


def guess_sources_and_targets_from_dir(dir_path):
    """
    Given a directory of stored processes, find which subset of the paths
    being read and written are candidates for source and target paths. Return
    two lists: sources and targets.
    """
    procs = load_from_dir(dir_path)
    return guess_sources_and_targets(procs)


def guess_sources_and_targets(procs):
    """
    Given a list of processes, find which subset of the paths being read and
    written are candidate source and target paths. Return two lists: sources
    and targets.
    """
    logger.info("Guessing sources and targets ...")
    all_reads, all_writes = file_lists(procs)
    # find the start and end of the build graph
    # possible sources were only ever read and never written to
    sources = all_reads - all_writes
    # possible targets were only ever written and never read to
    targets = all_writes - all_reads
    return tuple(sources), tuple(targets)


def analyze_deployment_graph_from_dir(dir_path, settings):
    """
    Given a directory of stored processes, analyze deployment.
    """
    procs = load_from_dir(dir_path)
    return analyze_full_graph(procs, settings)


def analyze_deployment_graph_from_dir_to_file(dir_path, out_file, settings):
    import csv

    with open(out_file, "w") as csvfile:
        wrtr = csv.writer(csvfile)
        for src_tgt in analyze_deployment_graph_from_dir(dir_path, settings):
            wrtr.writerow(src_tgt)
    logger.info("Analysis completed. ")


def debug_print(dir_path, pid):
    """
    Given a directory of stored processes, analyze deployment.
    """
    if pid:
        procs = load(dir_path, [pid])
    else:
        procs = load_from_dir(dir_path)
    for proc in procs:
        print(proc.pformat())
        print("---")


##############################################################################
# Command line processing

from tracecode._vendor.docopt import docopt

NOTICE = (
    """TraceCode version %s
Copyright (c) 2017 nexB Inc. All rights reserved. http://github.com/nexB/tracecode-build
"""
    % __version__
)

COMMAND_HELP = """
TraceCode analyze file transformations from a traced command execution.
For instance, trace a build and determine which source files are built into
target binary files.

Start by tracing a command with strace v4.8+:
  strace -ff -y -ttt -qq -a1 -o TRACE_DIR/<trace name> <your command>
For example:
  strace -ff -y -ttt -qq -a1 -o TRACE_DIR/make-trace make -j42

Then use TraceCode to analyze the traced command execution.

Command form:
 tracecode.py <options> <command> <arguments>

Usage:
 tracecode [options] parse     TRACE_DIR   PARSED_DIR
 tracecode [options] filter    PARSED_DIR  [NEW_PARSED_DIR]
 tracecode [options] list      PARSED_DIR  READS_FILE  WRITES_FILE
 tracecode [options] analyze   PARSED_DIR  ANALYSIS_FILE
 tracecode [options] graphic   PARSED_DIR  GRAPH_FILE
 tracecode [options] guess     PARSED_DIR  SOURCES_FILE  TARGETS_FILE
 tracecode [options] debug     PARSED_DIR
 tracecode [options] debugg    PARSED_DIR
 tracecode [options] validate  TRACE_DIR
 tracecode [options] inventory PARSED_DIR  INV_FILE
 tracecode           defaults
 tracecode -v|--version | -h|--help | -n|--notice

Arguments:
 *_FILE    Input or output file.
 *_DIR     Input or output directory.
 PATH      Absolute plain path to a source or target file.
 PATTERN   Plain path or glob pattern (using fnmatch(1)) matching a path.
           Patterns match an entire absolute path. A single pattern can be
           provided as a command line option. Multiple patterns can be loaded
           from file, one pattern per line. When using a single pattern quote
           the pattern to prevent shell expansion. For example to match all
           files in the directory tree /root/src/ use --src="/root/src/*".
           Complex file sets can be defined by combining inclusions and
           exclusions patterns. Exclusions patterns start with '-' (dash) and
           have precedence over regular inclusion patterns. Patterns loaded
           from a file with a .csv extension are loaded as CSV: the first
           column is used as patterns and other columns are ignored.

Commands:
 parse
  Parse traces in TRACE_DIR and save results to PARSED_DIR. All commands depend
  on this first step. Use the ignored_reads(_from) and ignored_writes(_from)
  options to filter path from the trace while parsing. Use the cwd option to
  set the initial directory for accurate relative paths resolution.

 list
  List the files read and written. Read parsed traces in PARSED_DIR and save
  lists of read files to READS_FILE and written files to WRITES_FILE.

 filter
  Filter parsed traces applying ignored_reads(_from) and ignored_writes(_from)
  options. Read parsed traces in PARSED_DIR and save results to NEW_PARSED_DIR.
  If NEW_PARSED_DIR is not specified, this command overwrites previous results
  stored in PARSED_DIR.

 guess
  Guess sources and targets files. Read parsed traces in PARSED_DIR and save
  guessed lists of source files to SOURCES_FILE and target files list to
  TARGETS_FILE. Sources are paths that are only read and never written to.
  Targets are paths that are only written and never further read.

 analyze
  Determine sources to targets files transformations. Read parsed traces in
  PARSED_DIR and save output to ANALYSIS_FILE as lines of comma-separated
  <source file path>,<target file path>. Use the --sources PATH or
  --sources_from FILE options and the --targets PATH or --targets_from FILE
  options as sources and targets. File transformations are analyzed from targets
  to sources: there are typically more sources than targets.

 graphic
  Create file transformations graphic. Read parsed traces in PARSED_DIR and
  save graphic to GRAPH_FILE. Default format is pdf and is specified with the
  format option. Require Graphviz installed and available in the path. Use the
  targets(_from) options to focus the graphic on a subset of targets. If
  targets(_from) PATTERN match more than one target file, ONLY the first target
  is graphed for now. In future version a new graphic file will be created for
  each target file. Note that creating a graphic for large traces takes a long
  time and may be too large to display.

 defaults
  Print default options formatted as configuration file.

 dump
  Dump graph nodes and relationships in PARSED_DIR in a CSV file.

 debug
  Print all processes in PARSED_DIR (or only one process with --pid=PID).

 validate
  Validate the traces, find the root pid.

 inventory
  List the files read and written. Read parsed traces in PARSED_DIR
  and save output to INV_FILE as lines of comma-separated
  <file path>,<number of reads>,<number of writes>.

Options:
"""


def check_dir(pth, label):
    if not os.path.exists(pth) or not os.path.isdir(pth):
        print("%(label)s directory %(pth)s does not exist or is " "not a directory." % locals())
        sys.exit(errno.EEXIST)


def get_dir(args, opt):
    dir_arg = args[opt]
    if dir_arg:
        dir_arg = os.path.normpath(os.path.expanduser(dir_arg))
        dir_arg = os.path.abspath(dir_arg)
        check_dir(dir_arg, opt)
    return dir_arg


def main(args):
    quiet = args.get("--quiet")
    logging.basicConfig(level=logging.ERROR if quiet else logging.INFO)

    if args.get("--notice"):
        print(NOTICE)
        sys.exit(1)

    if args.get("defaults"):
        ds = conf.DefaultSettings()
        print(ds.formatted())
        sys.exit(1)

    main_start_time = time.time()

    settings = conf.settings(args)
    if args.get("parse"):
        input_dir = get_dir(args, "TRACE_DIR")
        output_dir = get_dir(args, "PARSED_DIR")
        cwd_dir = args.get("--cwd")
        parse_raw_traces(cwd_dir, input_dir, output_dir, settings)

    elif args.get("filter"):
        input_dir = get_dir(args, "PARSED_DIR")
        # optional arg: if not set, overwrites INPUT_DIR
        output_dir = None
        if args["NEW_PARSED_DIR"]:
            output_dir = get_dir(args, "NEW_PARSED_DIR")
        cleaner(None, input_dir, output_dir, settings)

    elif args.get("list"):
        input_dir = get_dir(args, "PARSED_DIR")
        reads_file = args["READS_FILE"]
        writes_file = args["WRITES_FILE"]
        debug = args["--debug"]
        save_file_lists(input_dir, reads_file, writes_file, debug=debug)

    elif args.get("guess"):
        input_dir = get_dir(args, "PARSED_DIR")
        sources_file = args["SOURCES_FILE"]
        targets_file = args["TARGETS_FILE"]
        save_guessed_sources_and_targets(input_dir, sources_file, targets_file)

    elif args.get("analyze"):
        input_dir = get_dir(args, "PARSED_DIR")
        analysis_file = args["ANALYSIS_FILE"]

        # FIXME: having only targets is a valid use case
        if not settings.targets or not settings.sources:
            print("Aborting: No sources or targets defined for analysis.")
            sys.exit(1)
        analyze_deployment_graph_from_dir_to_file(input_dir, analysis_file, settings)

    elif args.get("graphic"):
        input_dir = get_dir(args, "PARSED_DIR")
        file_name = args["GRAPH_FILE"]
        file_type = args["--format"]
        as_graphic_from_dir(input_dir, file_name, settings, file_type=file_type)

    elif args.get("debug"):
        input_dir = get_dir(args, "PARSED_DIR")
        pid = args["--pid"]
        if pid:
            pid = int(pid)
        debug_print(input_dir, pid)

    elif args.get("dump"):
        input_dir = get_dir(args, "PARSED_DIR")
        file_name = args["DUMP_FILE"]
        dump_dir_to_csv(input_dir, file_name, settings)

    elif args.get("debugg"):
        input_dir = get_dir(args, "PARSED_DIR")
        debug_graph_print(input_dir, settings)

    elif args.get("validate"):
        input_dir = get_dir(args, "TRACE_DIR")
        logger.log(logging.INFO, "Processing traces from input_dir: " "%(input_dir)r." % locals())
        _root_pid, _traces = validate_traces(input_dir)

    elif args.get("inventory"):
        input_dir = get_dir(args, "PARSED_DIR")
        inv_file = args["INV_FILE"]
        save_file_lists_with_counts(input_dir, inv_file)

    main_duration = time.time() - main_start_time
    logger.info("Completed in %(main_duration).2f seconds." % locals())


def cli(*args, **kwargs):
    """
    Command line entry point.
    """
    arguments = docopt(NOTICE + COMMAND_HELP + conf.FORMATTED_OPTIONS, version=__version__)
    main(arguments)


if __name__ == "__main__":
    cli()
else:
    # always have some config for logging if not set
    logging.basicConfig(level=logging.INFO)

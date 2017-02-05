Tracing a build on Linux
========================

TraceCode is a tool to trace the execution of a build, so you can learn which
files are read, compiled, built and ultimately deployed.

This document provides guidelines on how to collect the trace a of build to
analyze later with TraceCode.

This trace is collected with an open source tool called strace. 
strace is BSD- licensed and available at: 
http://sourceforge.net/projects/strace/


You must use strace v.4.9 or later either from:
 - your Linux distribution (if it has strace 4.9 or higher)
 - built from sources from http://sourceforge.net/project/strace/
   BUILDING INSTRUCTIONS FOR STRACE ARE PROVIDED IN SECTION 2.


0. Basic system requirements on the build host
=============================

You need first:
 * a Linux-based build host (the machine on which you run the build).
 * sudo or root access on this build host.
 * plenty of disk space, typically 100GB free space or more for some large builds


Additional reference information:

    The set of files created during the trace of a build can be as big or
    bigger than your codebase. The rule of thumb is that the space needed to
    store the trace of a build may be roughly as big as the space needed to
    store the combination of all the intermediate files (such as .o and
    .class) and final built files (such as .so and .jar) created during the
    build. Assuming about 100GB of free space just for storing the build
    traces uncompressed should be enough to store even the largest build
    traces.

    Many small files are created during the tracing process, all in one
    directory (up to 500K files) which could be a problem on some file
    systems. This is usually not a problem with recent filesystems such as
    ext4 or similar.



1. Increase the PIDs limit of the build machine
=============================

To do this, run this configuration only once::
    $ sudo su -
    $ echo 4194303 > /proc/sys/kernel/pid_max
    then exist root with Ctrl-D


Additional reference information:

    For large builds, it may be necessary to increase the pid_max (the max
    number of process IDs) which defaults to 32768 in most cases.  Why
    increase the pid_max? Because strace creates one log file per process
    spawned during the build, using the PID (process id) as the saved trace
    file name.  A large build may easily spawn more than 100K processes and we
    need to have a unique filename per pid. If the max number of PID is
    reached, the PID restarts at one; previously saved trace files for a given
    PID could be overwritten with the same PID number.  For instance compiling
    each source file will spawn a new compiler process and a new trace file
    will be created for each process.  A Linux kernel contains 30 to 40K files
    and compiling a kernel may spawn 30 to 40K processes and therefore the PID
    may rollover to one if you use the default pid_max setting.  Very large
    and long running builds can spawn up to a million different processes.

    You can check the PID max with::

        $ cat /proc/sys/kernel/pid_max
        32768

    32768 is the typical default value on most Linux installations. To
    increase the PID to 4194303 use the command below. (note: the value
    4194303 is the highest supported value on 32 bit systems and is high
    enough for all known cases)::

        $ sudo su -
        $ echo 4194303 > /proc/sys/kernel/pid_max
        then exist root with Ctrl-D



2. Build and install strace
=============================
If you build strace from sources (as opposed to use a distro package for strace 4.9
or higher) use these additional instructions.

Install these packages:

 * basic packages installed on the build host (such as build-essential on 
   debian) and libtool, automake and autoconf.

   On Debian or Debian-derivatives such as Ubuntu you might need something
   like:
     sudo apt-get install build-essential automake autotools-dev autoconf \
     libtool

   On RPM-based Linuxes such as Fedora or OpenSuse you might need something
   like:
     sudo yum groupinstall "Development Tools"
     sudo yum install automake autotools autoconf libtool

Install the latest strace by building it from sources at:
    http://sourceforge.net/project/strace/

Additional reference information:
    DO NOT USE an strace package from an strace version before v4.9 if provided
    with your build host Linux distribution: it can be buggy at times or be an
    older version that does not contain the required features set.

Build and install strace this way::
    wget http://master.dl.sourceforge.net/project/strace/strace/4.15/strace-4.15.tar.xz
    tar -xzf 4.15.tar.xz
    cd strace-4.15
    autoreconf -i
    ./configure
    make

NOTE: installing strace globally in your system is optional.
You can run it from its build location too.
To install globally in /usr/local/bin/strace use::
    sudo make install


3. Prepare the build you want to trace
=============================

3.1 Ensure your build is ready to run and properly configured.
-----------------
Wipe clean and/or disable any compilation cache (such as ccache, bref).
Make clean or distclean or equivalent.


Additional reference information:
    You MUST ensure that the build is fully cleaned first. Run a make clean or
    a similar command to ensure that all artifacts of previous build runs are
    deleted including:

     - clearing object caches if you use caching compiler such as ccache.
     Use ccache --clear to clear a ccache cache.

     - clearing download caches if you use library repositories fetched
     remotely at build time such as with maven.

     - removing all intermediate and final compiled or built object, archives
     or deployed images


3.2 Save a tarball of the initial development codebase before the build.
---------------------------------

Create a tarball of the whole clean codebase BEFORE running the build. This
can include a custom toolchain if you do not use the standard installed
compiler and toolchain from your build host. This initial snapshot of the
codebase should contain all the files (either source or pre-compiled) that are
used in the build.

Use this tarball in step 5



4. Trace your build(s)
======================

Run as root if your build use sudo or setuid commands.

If you need multiple commands, trace each command, ensuring you use a
DIFFERENT output directory for each command.

Do a regular release build, NOT a debug build.


Additional reference information:
    If your build requires more than one command, execute this process once
    for each command. Ensure that you create a NEW DISTINCT trace output
    directory (a.k.a. {tracing_dir} for each build command that you trace.

    With strace, programs that use the setuid bit do not have effective user
    ID privileges while being traced. If your build use setuid privileges such
    as to create filesystems or special files with mknod or if you build use
    sudo, you will need to execute strace as ROOT. There are possibilities to
    use the -u option as an extra setting, passing -u <user> as the user that
    should be set by strace when doing setuid related operations.

    Your build should NOT BE INTERACTIVE such as asking password for su or
    sudo (for example if it needs to create special files as root, rather than
    using something like fakeroot). In cannot either use commands that use
    setuid. This is a limitation os strace and the Linux Kernel itself. In
    this case, run your build as root.

    If your build is run by a user with setuid privileges these privileges
    will be ignored during tracing and you will need need to run the build as
    sudo or root too.

    If your build is interactive, you need to find a way to run it with
    arguments or variables such that it can run end to end as one unattended
    command. You can write a small wrapper script for this purpose.


4.1. Collect the build trace with strace
----------------------------------------

Trace each of your build commands with strace, replacing the names in braces
{} with your actual build command and args, output directory and prefix. Use
$(which strace) if you installed strace globally or use the path to the strace
build directory if you did not install strace.

Execute your build under strace with this command::
    $(which strace) -ff -y -ttt -qq -a1 \
    -o {NEW EMPTY tracing_dir}/{trace prefix: project name, build number or version} \
    {build command}

For instance to run a simple make -j2, use this command::
    mkdir ~/mybuild-trace1
    $(which strace) -ff -y -ttt -qq -a1 -o ~/mybuild-trace1/myprod-v2 make -j2


Additional reference information:
    For each build command you need to run, create a NEW EMPTY directory
    __OUTSIDE of your build and codebase directory tree___ to store contain
    the output of each traced build command. We will refer to this directory
    as {tracing_dir}.

    Ensure that you create a NEW EMPTY {tracing_dir} directory for each traced
    build command. Do not mix several commands traces output in the same
    directory.

    If a build fails and needs to be restarted, create a NEW EMPTY directory
    when you rerun the build. Ensure you clean the build entirely before
    reruning it. Traces of partial builds cannot be interpreted correctly.


4.2. Wait for the build to complete
-------------------------------------------------------

A traced build will take from 3 to 10 times longer than a regular build. Using
a multi-threaded build helps (such as using the -j option with make) if your
build supports it.  A rule of thumb for make is to use -j x+2 where x is the
number of cores on the build machine.


4.3. Verify that your build completed correctly
-----------------------------------------------

Check that your final build artifacts were created correctly by the build and
that your build did not have any error.



5. Collect archives for the built codebase, traces and build outputs.
=============================

Create a tarball of the built codebase after running the build including all
the deployed codebase directories and the final deployed images or archives.

Make sure to include the 'out' directory or a similar directory that contains
all intermediate objects if the build artifacts are not created in-place in
the development codebase but in a separate 'out-style' directory.

It is best if and perfectly OK if this archive also contains again a copy of
the full development code.

Create a tarball of the build traces stored in every {tracing_dir}. Ensure
that you create one separate tarball for each traced build command output
directory.

Collect the tarball of the development codebase BEFORE the build created in
step 3.2.

You can then use these archives to trace your build with the tracecode tool.

Tracing a build on Linux
========================

TraceCode is a tool to analyze the traced execution of a build, so you can learn
which files are built into binaries and ultimately deployed in your distributed 
software.

This TraceCode toolkit uses strace to capture the system-level trace of a build
and can reconstruct how the build transforms and compiles files from this trace
aka. the build graph.


1. Tracing a build
-------------------------

See README-build-tracing.rst for tracing a build


2. System requirements and installation
---------------------------------------

Ensure you have Python installed::
    python -v

Install it as needed if not installed, ensuring that it is in your path. See you local Linux 
distributor for details.

Ensure you have Graphviz installed and in your path::
    dot -v

Install it as needed if not installed, ensuring that it is in your path.
See http://graphviz.org/ for details.

If not installed, you will see ERROR messages and the results are unlikely to
be usable.



3. Install TraceCode
--------------------

Get it from https://github.com/nexb/tracecode-toolkit-strace and unzip it.
The path were this is unzipped will be  referred to as <tracecode_dir> later
in this document. 

Then execute this command to setup TraceCode::

    ./configure --dev

Finally run the built-in selftest to verify your installation::

    py.test -vvs tests


4. Install strace
-----------------

One debian::

sudo apt-get strace


5. Analyze your build
---------------------

Analyzing a traced build is a multi-stage process that involves:

- parsing and checking the initial traces,

  - optionally filtering the parsed traces,

  - optionally collecting the inventory of files read and written during
    the build,

- creating the list of source (input) and target (output) files for your
  build,

- analyzing the build graph to determine the source to target relationships, 
  such as source code files being built into a binary,

  - optionally creating graphical representations to visualize subset of 
    your build graph.

Each of these steps is performed by invoking `tracecode` from the command line 
with different options and arguments.


Run the trace analysis with::

    tracecode <options> <command> <arguments> 


For command help use::

    tracecode -h 



Tutorial
========

See README-build-tracing.rst for extra details.


0. Trace a command
------------------

Use strace this way::

    $(which strace) -ff -y -ttt -qq -a1 \
    -o {NEW EMPTY tracing_dir}/{trace prefix} \
    {build command}

1. Parse the collected raw traces
---------------------------------

Create a new empty directory to store parsed traces. Then parse using the
"parse" command::
 
    tracecode parse <RAW TRACES DIR INPUT> <PARSED TRACES DIR OUTPUT>

This will parse the traces and ensure they can be processed and are complete



2. Collect the inventory of files processed during the tracing
----------------------------------------------------------------

If traces are consistent the next step is to collect the inventories of files
reads and writes. Use the "list" command (which should be called inventory).
It creates two files from a parsed trace:  a list of files being only read and
a list of files being written::

    tracecode list <PARSED TRACES DIR INPUT> <READS OUTPUT FILE> <WRITES OUTPUT FILE>

The list command extracts all the paths used in the traces.



3. optional but recommended: Filter your parsed traces
-------------------------------------------------------

The next step is to review these reads and writes and decide which ones could
be filtered out as they may not contribute interesting data to the build graph
and the analysis.

This includes typically:

    - /etc/* 
    - /proc/*
    - the build log files if any
    - Some standard things in /usr/* and similar

For this you build a list of reads to ignore and writes to ignore (usually
patterns or plain lists) you stuffs these two lists in a two files and use the
filter command to filter out these reads and writes.

Beware of not filtering too much: temp files in /tmp you want to keep certain
makedepend (.po, etc) files you may not care for.

When you filter at first filter to a new directory so taht you do not replace
the original full parsed traces yet, so you can get comfy and refine your
filtering.

Create a file that contains one line for each read or write you want to filter
out or prune from the trace Either a full path as found in the reads or writes
list, or a pattern as in /etc/* in which case everything matching /etc/* would
be filtered out like when you use glob patterns on the command line Use oe
path or pattern per line in a file. Note that it can be a single column csv
alright too.


4. optional: Guess sources and targets
----------------------------------------

You can use the "guess" command to guess sources and targets, but that is just
a guess. Guessing works ok on small well defined simple codebases, but might
noy likely be good on larger ones.

The guess goes this way:
 - files that are only ever read from are likely the source/devel
 - files that are only ever written to read are likely the target/deployed



5. Assemble the inventory of sources an targets
-----------------------------------------------

Once you have filtered your parsed trace, you need to create a list of  files
that are your sources, origin development files and another list that are your
targets, deployed files. You need to build theses inventories each in a
separate file. You can try the guess command, but that is just a wild guess
based on the graph. The paths should have exactly the same structure as in the
"list" output. The sources and targets files should be among the reads and
writes, so you can use these lists as an input. Alternatively you can use keep
an output of the find command before your tracing (your sources) and after and
diff it to find what would be the candidates.

Use these lists again to build new lists to define what is the list of
devel/sources files and what is the list of deployed/targets files.


6. Analyze sources to targets transformations
---------------------------------------------

Then you can run either the analyze command to get the source to target
deployment analysis.


7. optional: Graph select subset of sources to targets transformations
----------------------------------------------------------------------

You can selectively create a graphic tracing the transformation from several
sources to a one target or several targets to one sources with graphics
(selectively because this takes long time to run and large graphics are
impossible to visualize)



FAQ:
----

Q: When parsing raw traces I am getting this error::

    ERROR:tracecode:INCOMPLETE TRACE, 149249 orphaned trace(s) detected. First pid is: 3145728.

A: This is a serious error and means that your trace is not coherent as some
process traces could not be related to the initial command launch graph and
are therefore unrelated. This can happen if you mistakenly trace several
commands and store the strace output in the same directory. You need to
recollect your traces starting with a clean empty directory.


Q: When parsing raw traces I am getting several warnings::

    WARNING:tracecode:parse_line: Unable to decode descriptor for pid: 3097012, line: '1399882436.807573 dup2(5</extra/linux-2.6.32/scripts/mksysmap>, 255) = 255\n'

A: This is just a warning that you can ignore most of the times. Here a file
descriptor 255 does not (and cannot) exist, hence the warning.


Credits and related tools
-------------------------

This implementation of an strace-based build tracer is essentially an implementation
of these papers:

Sander van der Burg published a key article and paper:

- http://sandervanderburg.blogspot.be/2012/04/dynamic-analysis-of-build-processes-to.html
  "Discovering Software License Constraints:  Identifying a Binary's Sources by Tracing Build Processes"

- http://www.st.ewi.tudelft.nl/~sander/pdf/publications/TUD-SERG-2012-010.pdf
  By Sander van der Burg, Julius Davies, Eelco Dolstra,  Daniel M. German, Armijn Hemel.
  Technical Report TUD-SERG-2012-010, Software Engineering Research Group, Delft, The Netherlands, April 2012.  


Later, this similar paper relates the same approach:

- "Tracing Software Build Processes to Uncover License Compliance Inconsistencies"
  http://web.archive.org/web/20160329060541/http://shanemcintosh.org/assets/ase2014_vanderburg.pdf
  By Sander van der Burg, Eelco Dolstra, Shane McIntosh, Julius Davies, Daniel M. German, and Armijn Hemel


The Chromium test team built "swarming.client", a test isolation
tools that was also a big inspiration for this tool too:

- https://www.chromium.org/developers/testing/isolated-testing/infrastructure
- https://chromium.googlesource.com/external/swarming.client/


memoize.py and fabricate use strace to track file dependencies 
using a similar approach to this tool:

- https://github.com/kgaughan/memoize.py
- https://code.google.com/archive/p/fabricate/

- https://news.ycombinator.com/item?id=9356433 : This article provides some good
  background on the same topic.

- http://buildaudit.sourceforge.net/ is a related build tracing tool that
  handles ptrace directly ass opposed to rely on strace for tracing. 


License
=======

* Apache-2.0
* Multiple licenses (GPL2/3, LGPL, MIT, BSD, etc.) for third-party dependencies. 


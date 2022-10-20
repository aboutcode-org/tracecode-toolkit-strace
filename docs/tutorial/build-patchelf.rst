This mini tutorial guides you through a simple end to end build tracing.

Setup system (on Debian)
-----------------------------

We need some basic packages first::

    sudo apt-get install python3 build-essentials strace graphviz


Fetch archive and prepare for build:
---------------------------------------

We use patchelf which is a simple GPL-license executable::

    wget https://github.com/NixOS/patchelf/archive/f34751b88bd07d7f44f5cd3200fb4122bf916c7e.tar.gz
    tar -xf patchelf-f34751b88bd07d7f44f5cd3200fb4122bf916c7e.tar.gz
    mv patchelf-f34751b88bd07d7f44f5cd3200fb4122bf916c7e patchelf-f34751
    cd patchelf-f34751/
    ./bootstrap.sh 
    ./configure 
    cd ..


Fetch tracecode and configure
---------------------------------------

    git clone https://github.com/nexB/tracecode-toolkit-strace
    cd tracecode-toolkit-strace
    ./configure
    source venv/bin/activate
    cd ..


Trace the build
------------------------

::

    cd patchelf-f34751/
    mkdir -p TRACE
    mkdir -p PARSED

Run strace proper:
~~~~~~~~~~~~~~~~~~~

Compile patchelf "under" strace::

    strace -ff -y -ttt -qq -a1 -o TRACE/patchelf-trace make
    
    Making all in src
    make[1]: Entering directory '/home/user/tracing/patchelf-f34751/src'
    g++ -DPACKAGE_NAME=\"patchelf\" -DPACKAGE_TARNAME=\"patchelf\" -DPACKAGE_VERSION=\"0.12\" -DPACKAGE_STRING=\"patchelf\ 0.12\" -DPACKAGE_BUGREPORT=\"\" -DPACKAGE_URL=\"\" -DPACKAGE=\"patchelf\" -DVERSION=\"0.12\" -I.    -Wall -std=c++11 -D_FILE_OFFSET_BITS=64  -g -O2 -MT patchelf.o -MD -MP -MF .deps/patchelf.Tpo -c -o patchelf.o patchelf.cc
    mv -f .deps/patchelf.Tpo .deps/patchelf.Po
    g++ -Wall -std=c++11 -D_FILE_OFFSET_BITS=64  -g -O2   -o patchelf patchelf.o  
    make[1]: Leaving directory '/home/user/tracing/patchelf-f34751/src'
    Making all in tests
    make[1]: Entering directory '/home/user/tracing/patchelf-f34751/tests'
    make[1]: Nothing to be done for 'all'.
    make[1]: Leaving directory '/home/user/tracing/patchelf-f34751/tests'
    make[1]: Entering directory '/home/user/tracing/patchelf-f34751'
    make[1]: Nothing to be done for 'all-am'.
    make[1]: Leaving directory '/home/user/tracing/patchelf-f34751'


Check the trace files:
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

::

    ls -al TRACE/ | wc -l
    22


Process the build trace
----------------------------

::

    tracecode parse TRACE/ PARSED/
    INFO:tracecode:Processing traces with cwd: None, input_dir: '/home/user/tracing/patchelf-f34751/TRACE', output_dir: '/home/user/tracing/patchelf-f34751/PARSED'.
    INFO:tracecode:validate_traces: Found 19 traces with root pid: 26598.
    INFO:tracecode:validate_traces: Oldest pid: 26598.
    INFO:tracecode:validate_traces: Smallest pid: 26598.
    INFO:tracecode:Queuing trace of pid 26598 for parsing. Left to do: 18
    INFO:tracecode:Queuing trace of pid 26599 for parsing. Left to do: 17
    INFO:tracecode:Queuing trace of pid 26600 for parsing. Left to do: 16
    INFO:tracecode:Queuing trace of pid 26601 for parsing. Left to do: 15
    INFO:tracecode:Queuing trace of pid 26604 for parsing. Left to do: 14
    INFO:tracecode:Queuing trace of pid 26620 for parsing. Left to do: 13
    INFO:tracecode:Queuing trace of pid 26622 for parsing. Left to do: 12
    INFO:tracecode:Queuing trace of pid 26602 for parsing. Left to do: 11
    INFO:tracecode:Queuing trace of pid 26603 for parsing. Left to do: 10
    INFO:tracecode:Queuing trace of pid 26605 for parsing. Left to do: 9
    INFO:tracecode:Queuing trace of pid 26621 for parsing. Left to do: 8
    INFO:tracecode:Queuing trace of pid 26606 for parsing. Left to do: 7
    INFO:tracecode:Queuing trace of pid 26613 for parsing. Left to do: 6
    INFO:tracecode:Queuing trace of pid 26614 for parsing. Left to do: 5
    INFO:tracecode:Queuing trace of pid 26615 for parsing. Left to do: 4
    INFO:tracecode:Queuing trace of pid 26616 for parsing. Left to do: 3
    INFO:tracecode:Queuing trace of pid 26607 for parsing. Left to do: 2
    INFO:tracecode:Queuing trace of pid 26612 for parsing. Left to do: 1
    INFO:tracecode:Queuing trace of pid 26617 for parsing. Left to do: 0
    INFO:tracecode:All 19 traces queued for parsing in 0.14 seconds.
    INFO:tracecode:Filtering and saving cleaned traces to '/home/user/tracing/patchelf-f34751/PARSED'.
    INFO:tracecode:Applied filters to 19 traces in 0.00 seconds.
    INFO:tracecode:Filtered 1 empty traces from '/home/user/tracing/patchelf-f34751/PARSED' with 2 cycles in 0.00 seconds.
    INFO:tracecode:Processing completed in 0.85 seconds. All 19 traces parsed and saved to: "/home/user/tracing/patchelf-f34751/PARSED".
    INFO:tracecode:Completed in 0.86 seconds.


Generate a PDF of the build graph::

    tracecode graphic PARSED/ patchelf-build-graph
    INFO:tracecode:Loading traces ...
    INFO:tracecode:Building graph ...
    INFO:tracecode:Building subgraph for None...
    INFO:tracecode:Building and saving graphic file ...
    INFO:tracecode:Completed in 0.22 seconds.


Now open patchelf-build-graph.pdf to display the build graph.
This is also availabel in this directory as patchelf-build-graph.pdf




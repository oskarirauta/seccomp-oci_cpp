[![License:MIT](https://img.shields.io/badge/License-MIT-blue?style=plastic)](LICENSE)
[![C++ CI build](../../actions/workflows/build.yml/badge.svg)](../../actions/workflows/build.yml)

### seccomp-oci_cpp
Seccomp library that accepts OCI configuration

### <sub>Description</sub>
Library can be used to parse very nearly OCI spec compliant json's
seccomp section and to apply seccomp filtering.

### <sub>Story</sub>
I am not a specialist with seccomp, there was a big learning curve,
where other existing libraries and software were a great starting
point, mostly libseccomp and Openwrt's procd helped out a lot.

### <sub>Testing</sub>
It was difficult to test how well this worked out, especially
on syscall args, but finally with personality tests I got a
sample config that was able to be used for proper testing -
so far everything works.

### <sub>Possible problems</sub>
Parser is case in-sensitive. To be OCI compliant, it is correct
way, but I wonder, would it be better if it would be more tolerant?

### <sub>How to use this?</sub>
This time my README is a stub and you need to check sample
code in examples directory to see how to use this. But to implement
this library to your own code, you need to clone it and it's submodules,
include Makefile.inc and link against $SECCOMP_OBJECTS, see Makefile for
example.

### <sub>Parsing json</sub>
Parsing support seccomp section from OCI spec, but you can also
provide it full OCI spec json, it has a feature to iterate to
seccomp section.

### <sub>Samples and testing</sub>
Calling make, will build the library along with example code and some
test commands to show how args feature works with personality. It will
compile pfail1, pfail2 and psucceed - these are minimal programs that
only attempt to set persona, and report if it was success or not - when
example code is executed, it will parse seccomp config from seccomp.json,
build and install filter, and then it starts shell. In executed shell
pfail1 and pfail2 will fail to permission error, because in seccomp.json 
personas that they try to set, are black listed, psucceed shows that
setting personality still works, because personality that it tries to
set - is not black listed. Some other syscalls are also black listed,
such as rmdir, mkdir, uname and chdir - this means that inside shell
you are not allowed to create or remove directories, retrieve full
data using uname and you are jailed to current working directory.

### <sub>Syscall support</sub>
Syscalls might vary depending on your kernel and it's headers - therefore
2 scripts are provided, make_syscall_enum.sh and make_syscall_types.sh.
Make system uses these automaticly to parse supported syscalls from
your linux headers. Scripts are based on existing scripts by other people
with BSD style licenses.

### <sub>Note</sub>
Partly I did this for study purposes, seccomp is well documented, but
on many cases documentation provides only minimal set of functionality
to get you started. Also other software available felt pretty complex
to me, mostly because it was written in C, which lacks containers
such as maps, sets and vectors that can greatly simplify your project.
Because I wrote it in C++, I was able to divide code to smaller
sections and keep it pretty simple; hoping that anyone else wanting
to study on how to utilize seccomp in their software, this would
give another good starting point.

### <sub>Library</sub>
By default, build process also produces both shared and static libraries
and links example program against static library. To link against dynamic
library, pass SHARED_LINKING=yes environment variable for make. This though
means that you need to manually install libseccomp-oci.a to /usr/lib to be
able to execute program. My build system does not come with any automated
install system.

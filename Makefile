all: world

CXX?=g++
CXXFLAGS?=--std=c++17 -Wall -fPIC -g

OBJS:= \
	objs/main.o

SHARED_LINKING?=no

SECCOMP_DIR:=.
include ./Makefile.inc
include json/Makefile.inc
include common/Makefile.inc

world: libseccomp-oci.so libseccomp-oci.a example pfail1 pfail2 psucceed

$(shell mkdir -p objs)

objs/main.o: examples/main.cpp
	$(CXX) $(CXXFLAGS) $(INCLUDES) -c -o $@ $<;

objs/pfail1.o: examples/persona.cpp
	$(CXX) -DPERSONA=131072 $(CXXFLAGS) $(INCLUDES) -c -o $@ $<;

objs/pfail2.o: examples/persona.cpp
	$(CXX) -DPERSONA=131080 $(CXXFLAGS) $(INCLUDES) -c -o $@ $<;

objs/psucceed.o: examples/persona.cpp
	$(CXX) -DPERSONA=4294967295 $(CXXFLAGS) $(INCLUDES) -c -o $@ $<;

libseccomp-oci.so: $(JSON_OBJS) $(SECCOMP_OBJS)
	$(CXX) -shared -Wl,-soname,libseccomp-oci.so -o $@ $^

libseccomp-oci.a: $(JSON_OBJS) $(SECCOMP_OBJS)
	$(AR) rcs $@ $^

pfail1: objs/pfail1.o
	$(CXX) $(CXXFLAGS) $(LDFLAGS) $^ -o $@;

pfail2: objs/pfail2.o
	$(CXX) $(CXXFLAGS) $(LDFLAGS) $^ -o $@;

psucceed: objs/psucceed.o
	$(CXX) $(CXXFLAGS) $(LDFLAGS) $^ -o $@;

ifeq ($(SHARED_LINKING),yes)
example: $(OBJS)
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -L. -lseccomp-oci $^ -o $@;
else
example: $(OBJS) libseccomp-oci.a
	$(CXX) $(CXXFLAGS) $(LDFLAGS) $^ -o $@;
endif

.PHONY: clean
clean:
	@rm -rf objs example pfail1 pfail2 psucceed libseccomp-oci.so libseccomp-oci.a


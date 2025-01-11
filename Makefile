all: world

CXX?=g++
CXXFLAGS?=--std=c++17 -Wall -fPIC -g

OBJS:= \
	objs/main.o

SECCOMP_DIR:=.
include ./Makefile.inc
include json/Makefile.inc
include common/Makefile.inc

world: example pfail1 pfail2 psucceed

$(shell mkdir -p objs)

objs/main.o: examples/main.cpp
	$(CXX) $(CXXFLAGS) $(INCLUDES) -c -o $@ $<;

objs/pfail1.o: examples/persona.cpp
	$(CXX) -DPERSONA=131072 $(CXXFLAGS) $(INCLUDES) -c -o $@ $<;

objs/pfail2.o: examples/persona.cpp
	$(CXX) -DPERSONA=131080 $(CXXFLAGS) $(INCLUDES) -c -o $@ $<;

objs/psucceed.o: examples/persona.cpp
	$(CXX) -DPERSONA=4294967295 $(CXXFLAGS) $(INCLUDES) -c -o $@ $<;

pfail1: objs/pfail1.o
	$(CXX) $(CXXFLAGS) $(LDFLAGS) $^ -o $@;

pfail2: objs/pfail2.o
	$(CXX) $(CXXFLAGS) $(LDFLAGS) $^ -o $@;

psucceed: objs/psucceed.o
	$(CXX) $(CXXFLAGS) $(LDFLAGS) $^ -o $@;

example: $(JSON_OBJS) $(SECCOMP_OBJS) $(OBJS)
	$(CXX) $(CXXFLAGS) $(LDFLAGS) $^ -o $@;

.PHONY: clean
clean:
	@rm -rf objs example pfail1 pfail2 psucceed


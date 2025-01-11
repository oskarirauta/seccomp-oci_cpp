SECCOMP_DIR?=./seccomp
INCLUDES += -I$(SECCOMP_DIR)/include

SECCOMP_OBJS:= \
	objs/seccomp_arch.o \
	objs/seccomp_action.o \
	objs/seccomp_arg.o \
	objs/seccomp_syscall.o \
	objs/seccomp_config.o \
	objs/seccomp_error.o \
	objs/seccomp_parse.o \
	objs/seccomp_filter.o \
	objs/seccomp_rule.o \
	objs/seccomp_describe.o \
	objs/seccomp_seccomp.o

$(shell mkdir -p $(SECCOMP_DIR)/include/seccomp/types)
$(shell \
	[ -f "$(SECCOMP_DIR)/include/seccomp/types/syscall_names.inc" ] \
		|| $(SECCOMP_DIR)/make_syscall_enum.sh $(CXX) > $(SECCOMP_DIR)/include/seccomp/types/syscall_names.inc \
)
$(shell \
	[ -f "$(SECCOMP_DIR)/src/syscall_types.inc" ] \
		|| $(SECCOMP_DIR)/make_syscall_types.sh $(CXX) > $(SECCOMP_DIR)/src/syscall_types.inc \
)

objs/seccomp_arch.o: $(SECCOMP_DIR)/src/arch.cpp
	$(CXX) $(CXXFLAGS) $(INCLUDES) -c -o $@ $<;

objs/seccomp_action.o: $(SECCOMP_DIR)/src/action.cpp
	$(CXX) $(CXXFLAGS) $(INCLUDES) -c -o $@ $<;

objs/seccomp_arg.o: $(SECCOMP_DIR)/src/arg.cpp
	$(CXX) $(CXXFLAGS) $(INCLUDES) -c -o $@ $<;

objs/seccomp_syscall.o: $(SECCOMP_DIR)/src/syscall.cpp
	$(CXX) $(CXXFLAGS) $(INCLUDES) -c -o $@ $<;

objs/seccomp_config.o: $(SECCOMP_DIR)/src/config.cpp
	$(CXX) $(CXXFLAGS) $(INCLUDES) -c -o $@ $<;

objs/seccomp_error.o: $(SECCOMP_DIR)/src/error.cpp
	$(CXX) $(CXXFLAGS) $(INCLUDES) -c -o $@ $<;

objs/seccomp_parse.o: $(SECCOMP_DIR)/src/parse.cpp
	$(CXX) $(CXXFLAGS) $(INCLUDES) -c -o $@ $<;

objs/seccomp_filter.o: $(SECCOMP_DIR)/src/filter.cpp
	$(CXX) $(CXXFLAGS) $(INCLUDES) -c -o $@ $<;

objs/seccomp_rule.o: $(SECCOMP_DIR)/src/rule.cpp
	$(CXX) $(CXXFLAGS) $(INCLUDES) -c -o $@ $<;

objs/seccomp_describe.o: $(SECCOMP_DIR)/src/describe.cpp
	$(CXX) $(CXXFLAGS) $(INCLUDES) -c -o $@ $<;

objs/seccomp_seccomp.o: $(SECCOMP_DIR)/src/seccomp.cpp
	$(CXX) $(CXXFLAGS) $(INCLUDES) -c -o $@ $<;

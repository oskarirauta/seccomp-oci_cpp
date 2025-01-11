#include <linux/types.h>
#include <linux/seccomp.h>

#include "seccomp/arg.hpp"
#include "seccomp/rule.hpp"

size_t SECCOMP::RULE::syscalls_size() const {

	return this -> syscalls.size();
}

size_t SECCOMP::RULE::args_size() const {

	size_t s = 0;
	for ( const auto& arg : this -> args )
		s += arg.is_masked() ? 3 : 2;
	return s;
}

size_t SECCOMP::RULE::size() const {

	if ( this -> syscalls.empty())
		return 0;

	return this -> syscalls_size() + this -> args_size();
}

bool SECCOMP::RULE::empty() const {

	return this -> syscalls.empty();
}

void SECCOMP::RULE::for_each_syscall(const SECCOMP::RULE::for_each_syscall_function lambda) const {

	size_t sz = this -> syscalls_size();
	size_t idx = 0;
	size_t allow_idx = 1;
	size_t deny_idx = sz - 1;
	size_t az = this -> args_size();

	if ( az > 0 )
		allow_idx += az;

	for ( auto it = this -> syscalls.begin(); it != this -> syscalls.end(); it++ ) {

		SECCOMP::SYSCALL sc = *it;
		SC_ELEMENT elem = { .idx = idx++, .deny_idx = deny_idx--, .allow_idx = sz == idx ? allow_idx : (size_t)0, .sc = sc.value() };
		lambda(elem);

		if ( az > 0 )
			allow_idx--;
	}
}

static __u32 arg_offset(int offset) {

	switch ( offset ) {
		case 1: return (__u32)offsetof(seccomp_data, args[1]);
		case 2: return (__u32)offsetof(seccomp_data, args[2]);
		case 3: return (__u32)offsetof(seccomp_data, args[3]);
		case 4: return (__u32)offsetof(seccomp_data, args[4]);
		case 5: return (__u32)offsetof(seccomp_data, args[5]);
		case 6: return (__u32)offsetof(seccomp_data, args[6]);
		default: return (__u32)offsetof(seccomp_data, args[0]);
	}

	return (__u32)offsetof(seccomp_data, args[0]);
}

void SECCOMP::RULE::for_each_arg(const SECCOMP::RULE::for_each_arg_function lambda) const {

	size_t sz = this -> args_size();
	size_t idx = 0;
	size_t deny_idx = sz;

	for ( auto it = this -> args.begin(); it != this -> args.end(); it++ ) {

		SECCOMP::ARG arg = *it;
		deny_idx -= arg.is_masked() ? 3 : 2;

		ARG_ELEMENT elem = {
					.idx = idx++,
					.deny_idx = arg.is_inverted() ? (deny_idx == 0 ? (size_t)1 : (size_t)0) : deny_idx,
					.allow_idx = arg.is_inverted() ? deny_idx : ( deny_idx == 0 ? (size_t)1 : (size_t)0 ),
					.offset = arg_offset(arg.index),
					.inverted = arg.is_inverted(),
					.masked = arg.is_masked(),
					.nr = arg.value(),
					.value1 = arg.is_masked() ? arg.value2 : arg.value1,
					.value2 = arg.is_masked() ? arg.value1 : 0
		};

		lambda(elem);
	}
}

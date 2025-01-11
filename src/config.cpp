#include <sstream>
#include <linux/seccomp.h>
#include "seccomp/describe.hpp"
#include "seccomp/config.hpp"

#if defined(SECCOMP_MODE_STRICT)
static const int SECCOMP_STRICT_NR = (int)SECCOMP_MODE_STRICT;
#else
static const int SECCOMP_STRICT_NR = (int)1;
#endif

#if defined(SECCOMP_MODE_FILTER)
static const int SECCOMP_FILTER_NR = (int)SECCOMP_MODE_FILTER;
#else
static const int SECCOMP_FILTER_NR = (int)2;
#endif

void SECCOMP::CONFIG::clear() {

	this -> defaultAction = SECCOMP::ACTION::TYPE::KILL;
	this -> defaultAction.code = EPERM;
	this -> architectures.clear();
	this -> rules.clear();
	this -> flags.clear();
	this -> fail_unknown_syscall = true;
}

void SECCOMP::CONFIG::erase() {

	this -> clear();
}

int SECCOMP::CONFIG::seccomp_mode() {

	return this -> mode == SECCOMP::CONFIG::MODE::FILTER ? SECCOMP_FILTER_NR : SECCOMP_STRICT_NR;
}

int SECCOMP::CONFIG::seccomp_syscall_mode() {

	return this -> mode == SECCOMP::CONFIG::MODE::FILTER ? SECCOMP_SET_MODE_FILTER : SECCOMP_SET_MODE_STRICT;
}

int SECCOMP::CONFIG::flags_value() {

	int _flags = 0;

	if ( this -> flags[SECCOMP::CONFIG::FLAG::TSYNC]) _flags |= SECCOMP_FILTER_FLAG_TSYNC;
	if ( this -> flags[SECCOMP::CONFIG::FLAG::LOG]) _flags |= SECCOMP_FILTER_FLAG_LOG;
	if ( this -> flags[SECCOMP::CONFIG::FLAG::SPEC_ALLOW]) _flags |= SECCOMP_FILTER_FLAG_SPEC_ALLOW;
	//unsupported for now:
	//if ( this -> flags[SECCOMP::CONFIG::FLAG::WAIT_KILLABLE_RECV]) _flags |= SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV;

	return _flags;
}

bool SECCOMP::CONFIG::empty() const {

	return this -> architectures.empty() && this -> rules.empty();
}

SECCOMP::CONFIG::operator std::string() const {

	std::stringstream ss;

	ss << "seccomp mode: " << this -> mode;
	ss << "\nflags:" << ( this -> flags.empty() ? " none" : "" );
	for ( const auto flag : this -> flags )
		ss << " " << flag << ( flag == SECCOMP::CONFIG::FLAG::WAIT_KILLABLE_RECV ? "(ignored: unsupported)" : "" );

	ss << "\narchitectures:" << ( this -> architectures.empty() ? " none" : "" );
	for ( auto arch : this -> architectures )
		ss << " " << arch;

	ss << "\n\ndefault action: " << this -> defaultAction;
	ss << "\nrules:" << ( this -> rules.empty() ? " none" : "" );
	if ( this -> rules.empty())
		return ss.str();

	for ( auto rule : this -> rules ) {

		ss << "\n - action: " << rule.action;
		ss << "\n   syscalls:";

		for ( auto syscall : rule.syscalls )
			ss << " " << syscall;

		if ( !rule.args.empty()) {

			ss << "\n   args:";

			for ( auto arg : rule.args )
				ss << "\n        " << arg;
		}

		ss << "\n";
	}

	std::string s = ss.str();
	while ( s.back() == '\n' )
		s.pop_back();

	return s;
}

std::ostream& operator <<(std::ostream& os, const SECCOMP::CONFIG& config) {

	os << (std::string)config;
	return os;
}

std::ostream& operator <<(std::ostream& os, const SECCOMP::CONFIG* config) {

	os << (std::string)*config;
	return os;
}

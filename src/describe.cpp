#include "seccomp/config.hpp"
#include "seccomp/action.hpp"
#include "seccomp/syscall.hpp"
#include "seccomp/arch.hpp"
#include "seccomp/arg.hpp"
#include "seccomp/filter.hpp"
#include "seccomp/seccomp.hpp"
#include "seccomp/describe.hpp"

std::ostream& operator <<(std::ostream& os, const SECCOMP::CONFIG::MODE& mode) {

	os << (  mode == SECCOMP::CONFIG::MODE::FILTER ? "FILTER" : "STRICT" );
	return os;
}

std::ostream& operator <<(std::ostream& os, const SECCOMP::CONFIG::FLAG& flag) {

	if ( flag == SECCOMP::CONFIG::FLAG::TSYNC ) os << "TSYNC";
	else if ( flag == SECCOMP::CONFIG::FLAG::LOG ) os << "LOG";
	else if ( flag == SECCOMP::CONFIG::FLAG::SPEC_ALLOW ) os << "SPEC_ALLOW";
	else if ( flag == SECCOMP::CONFIG::FLAG::WAIT_KILLABLE_RECV ) os << "WAIT_KILLABLE_RECV";
	else os << "UNKNOWN_FLAG!";

	return os;
}

std::ostream& operator <<(std::ostream& os, const SECCOMP::ACTION& action) {

	os << action.name();
	return os;
}

std::ostream& operator <<(std::ostream& os, const SECCOMP::ARCH& arch) {

	os << arch.name();
	return os;
}

std::ostream& operator <<(std::ostream& os, const SECCOMP::SYSCALL& syscall) {

	os << syscall.ociname();
	return os;
}

std::ostream& operator <<(std::ostream& os, const SECCOMP::ARG& arg) {

	if ( arg == SECCOMP::ARG::TYPE::CMP_MASKED_EQ )
		os << "#" << arg.index << ": " << arg.value1 << " " << arg.name() << " " << arg.value2;
	else os << "#" << arg.index << ": " << arg.name() << " " << arg.value1;
	return os;
}

std::ostream& operator <<(std::ostream& os, const SECCOMP::FILTER& filter) {

	os << (std::string)filter;
	return os;
}

std::ostream& operator <<(std::ostream& os, const SECCOMP::FILTER* filter) {

	os << (std::string)*filter;
	return os;
}

std::ostream& operator <<(std::ostream& os, const SECCOMP& seccomp) {

        os << (std::string)seccomp;
        return os;
}

std::ostream& operator <<(std::ostream& os, const SECCOMP* seccomp) {

        os << (std::string)*seccomp;
        return os;
}

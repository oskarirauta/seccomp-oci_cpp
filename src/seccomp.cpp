#include <vector>
#include <cerrno>
#include <algorithm>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sys/syscall.h>
#include <sys/prctl.h>
#include <unistd.h>

#include "json.hpp"
#include "seccomp.hpp"
#include "seccomp/filter.hpp"

static bool seccomp_enabled = false;

bool SECCOMP::is_enabled() {

	return seccomp_enabled;
}

SECCOMP::CONFIG SECCOMP::config() const {

	SECCOMP::CONFIG cfg = *(this -> _config);
	return cfg;
}

SECCOMP::operator std::string() const {

	return this -> _bpf_code;
}

void SECCOMP::execute() {

	if ( seccomp_enabled )
		throw SECCOMP::exception(SECCOMP::ERROR_CODE::SECCOMP_ALREADY_ENABLED);

	if ( this -> _config -> empty())
		throw SECCOMP::exception(SECCOMP::ERROR_CODE::IGNORE_EMPTY_SECCOMP);

	if ( this -> _config -> mode == SECCOMP::CONFIG::MODE::STRICT ) {

		if ( ::prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0))
			throw SECCOMP::exception(SECCOMP::ERROR_CODE::SET_NO_NEW_PRIVS, "seccomp failed to set NO_NEW_PRIVS, " + std::string(::strerror(errno)));

		if ( ::prctl(PR_SET_SECCOMP, this -> _config -> seccomp_mode()))
			throw SECCOMP::exception(SECCOMP::ERROR_CODE::SET_SECCOMP_FILTER, "seccomp failed to set strict mode, " + std::string(::strerror(errno)));

		seccomp_enabled = true;
		this -> _bpf_code = "<seccomp strict mode>";
		return;
	}

	SECCOMP::CONFIG* config = this -> _config;
	SECCOMP::FILTER filter;
	SECCOMP::ARCH arch = SECCOMP::ARCH::current();

	// is this architecture allowed
	if ( !config -> architectures.empty() &&
		std::find_if(config -> architectures.begin(), config -> architectures.end(),
			[&arch](const SECCOMP::ARCH& a) {
				return arch.value() == a.value();
			}) == config -> architectures.end())
		throw SECCOMP::exception(SECCOMP::ERROR_CODE::ARCH_MISMATCH,
			"seccomp configuration does not allow execution on this architecture (" + arch.name() + ")");

	// arch filter
	filter.add({ .code = BPF_LD | BPF_W | BPF_ABS, .jt = 0, .jf = 0, .k = offsetof(seccomp_data, arch) });
	filter.add({ .code = BPF_JMP | BPF_JEQ | BPF_K, .jt = 1, .jf = 0, .k = arch.value() });
	filter.add({ .code = BPF_RET | BPF_K, .jt = 0, .jf = 0, .k = SECCOMP_RET_KILL });

	// rule filters
	for ( const auto& rule : config -> rules ) {

		filter.add({ .code = BPF_LD | BPF_W | BPF_ABS, .jt = 0, .jf = 0, .k = offsetof(seccomp_data, nr) });

		rule.for_each_syscall([&filter](SECCOMP::RULE::SC_ELEMENT& elem) {

			filter.add({
				.code = BPF_JMP | BPF_JEQ | BPF_K,
				.jt = (__u8)elem.deny_idx,
				.jf = (__u8)elem.allow_idx,
				.k = elem.sc
			});
		});

		rule.for_each_arg([&filter](SECCOMP::RULE::ARG_ELEMENT& elem) {

			filter.add({ .code = BPF_LD | BPF_W | BPF_ABS, .jt = 0, .jf = 0, .k = elem.offset });

			if ( elem.masked )
				filter.add({ .code = BPF_ALU | BPF_K | BPF_AND, 0, 0, (__u32)elem.value2 });

			filter.add({ .code = (__u16)(BPF_JMP | elem.nr | BPF_K),
					.jt = (__u8)elem.deny_idx,
					.jf = (__u8)elem.allow_idx,
					.k = (__u32)elem.value1
			});

		});


		filter.add({ .code = BPF_RET + BPF_K, .jt = 0, .jf = 0, .k = rule.action.value() });
	}

	filter.add({ .code = BPF_RET + BPF_K, .jt = 0, .jf = 0, .k = config -> defaultAction.value() });

	sock_fprog prog = { .len = (short unsigned int)filter.size(), .filter = filter.filter() };

	if ( ::prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0))
		throw SECCOMP::exception(SECCOMP::ERROR_CODE::SET_NO_NEW_PRIVS, "seccomp failed to set NO_NEW_PRIVS, " + std::string(::strerror(errno)));

	if (( config -> flags.empty() && ::prctl(PR_SET_SECCOMP, config -> seccomp_mode(), &prog)) ||
		( !config -> flags.empty() && ::syscall(SYS_seccomp, config -> seccomp_syscall_mode(), config -> flags_value(), &prog)))
		throw SECCOMP::exception(SECCOMP::ERROR_CODE::SET_SECCOMP_FILTER, "seccomp failed to set filter, " + std::string(::strerror(errno)));

	seccomp_enabled = true;
	this -> _bpf_code = (std::string)filter;

	if ( config -> flags[SECCOMP::CONFIG::FLAG::WAIT_KILLABLE_RECV])
		throw SECCOMP::exception(SECCOMP::ERROR_CODE::OCI_UNSUPPORTED_FEATURE, "seccomp flag SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV ignored, unsupported feature").fatal(false);
}

SECCOMP& SECCOMP::operator =(const SECCOMP::CONFIG& config) {

	if ( this -> _config == nullptr )
		this -> _config = new SECCOMP::CONFIG();

	this -> _config -> operator =(config);
	return *this;
}

SECCOMP::SECCOMP() {

	this -> _config = new SECCOMP::CONFIG();
}

SECCOMP::SECCOMP(const SECCOMP::CONFIG& config) {

	this -> _config = new SECCOMP::CONFIG();
	this -> _config -> operator =(config);
}

SECCOMP::~SECCOMP() {

	if ( this -> _config != nullptr )
		delete this -> _config;
}

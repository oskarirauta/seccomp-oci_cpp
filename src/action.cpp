#include <algorithm>
#include <linux/seccomp.h>

#include "seccomp/seccomp.hpp"
#include "seccomp/action.hpp"


#if defined(SECCOMP_RET_KILL)
const uint32_t _KILL = SECCOMP_RET_KILL;
#else
const uint32_t _KILL = 0x00000000U;
#endif

#if defined(SECCOMP_RET_TRAP)
const uint32_t _TRAP = SECCOMP_RET_TRAP;
#else
const uint32_t _TRAP = 0x00030000U;
#endif

#if defined(SECCOMP_RET_ERRNO)
const uint32_t _ERRNO = SECCOMP_RET_ERRNO;
#else
const uint32_t _ERRNO = 0x00050000U;
#endif

#if defined(SECCOMP_RET_LOG)
const uint32_t _LOGALLOW = SECCOMP_RET_LOG;
#else
const uint32_t _LOGALLOW = 0x7ffc0000U;
#endif

#if defined(SECCOMP_RET_TRACE)
const uint32_t _TRACE = SECCOMP_RET_TRACE;
#else
const uint32_t _TRACE = 0x7ff00000U;
#endif

#if defined(SECCOMP_RET_ALLOW)
const uint32_t _ALLOW = SECCOMP_RET_ALLOW;
#else
const uint32_t _ALLOW = 0x7fff0000U;
#endif

#if defined(SECCOMP_RET_KILLPROCESS)
const uint32_t _KILLPROCESS = SECCOMP_RET_KILLPROCESS;
#else
const uint32_t _KILLPROCESS = 0x80000000U;
#endif

const uint32_t _RETVALUE = 0x0000ffffU;

static const std::map<SECCOMP::ACTION::TYPE, SECCOMP::ACTION::MEMBER> actions = {
	{ SECCOMP::ACTION::TYPE::KILL, { .name = "kill", .ociname = "SCMP_ACT_KILL", .value = _KILL }},
	{ SECCOMP::ACTION::TYPE::KILLPROCESS, { .name = "killprocess", .ociname = "SCMP_ACT_KILL_PROCESS", .value = _KILLPROCESS }},
	{ SECCOMP::ACTION::TYPE::TRAP, { .name = "trap", .ociname = "SCMP_ACT_TRAP", .value = _TRAP }},
	{ SECCOMP::ACTION::TYPE::ERRNO, { .name = "errno", .ociname = "SCMP_ACT_ERRNO", .value = _ERRNO }},
	{ SECCOMP::ACTION::TYPE::TRACE, { .name = "trace", .ociname = "SCMP_ACT_TRACE", .value = _TRACE }},
	{ SECCOMP::ACTION::TYPE::ALLOW, { .name = "allow", .ociname = "SCMP_ACT_ALLOW", .value = _ALLOW }},
	{ SECCOMP::ACTION::TYPE::LOG, { .name = "logallow", .ociname = "SCMP_ACT_LOG", .value = _LOGALLOW }},
};

SECCOMP::ACTION::TYPE SECCOMP::ACTION::type() const {

	return this -> _type;
}

std::string SECCOMP::ACTION::name() const {

	return this -> _valid ? actions.at(this -> _type).name : "unknown";
}

std::string SECCOMP::ACTION::ociname() const {

	return this -> _valid ? actions.at(this -> _type).ociname : "";
}

uint32_t SECCOMP::ACTION::value() const {

	if ( !this -> _valid )
		return 0;
	else if ( this -> _type == SECCOMP::ACTION::TYPE::ERRNO )
		return _ERRNO | ((this -> code) & _RETVALUE);
	else return this -> _valid ? actions.at(this -> _type).value : 0;
}

bool SECCOMP::ACTION::valid() const {

	return this -> _valid;
}

SECCOMP::ACTION::operator bool() const {

	return this -> _valid;
}

bool SECCOMP::ACTION::operator ==(const SECCOMP::ACTION::TYPE& type) const {

	return this -> _valid && this -> _type == type;
}

bool SECCOMP::ACTION::operator !=(const SECCOMP::ACTION::TYPE& type) const {

	return !(*this == type);
}

bool SECCOMP::ACTION::operator ==(const std::string& name) const {

	if ( !this -> _valid )
		return false;

	std::string n = name;
	if ( n == "error" ) n = "errno";
	else if ( n == "SCMP_ACT_ERROR" ) n = "SCMP_ACT_ERRNO";

        if ( auto it = std::find_if(actions.begin(), actions.end(),
                [n](const std::pair<SECCOMP::ACTION::TYPE, SECCOMP::ACTION::MEMBER>& m) {
                        return m.second.name == n || m.second.ociname == n;
                }); it != actions.end()) {
		return true;
	}

	return false;
}

bool SECCOMP::ACTION::operator !=(const std::string& name) const {

	return !(*this == name);
}

bool SECCOMP::ACTION::operator ==(const uint32_t value) const {

	if ( auto it = std::find_if(actions.begin(), actions.end(),
		[value](const std::pair<SECCOMP::ACTION::TYPE, SECCOMP::ACTION::MEMBER>& m) {
			return m.second.value == value;
		}); it != actions.end()) {
		return true;
	}

	return false;
}

bool SECCOMP::ACTION::operator !=(const uint32_t value) const {

	return !(*this == value);
}

SECCOMP::ACTION& SECCOMP::ACTION::operator =(const SECCOMP::ACTION::TYPE& type) {

	this -> _type = type;
	this -> _valid = true;
	this -> code = EPERM;
	return *this;
}

SECCOMP::ACTION& SECCOMP::ACTION::operator =(const SECCOMP::ACTION& other) {

	this -> _type = other._type;
	this -> _valid = other._valid;
	this -> code = other.code;
	return *this;
}

SECCOMP::ACTION& SECCOMP::ACTION::operator =(const std::string& name) {

	std::string n = name;
	if ( n == "error" ) n = "errno";
	else if ( n == "SCMP_ACT_ERROR" ) n = "SCMP_ACT_ERRNO";

	SECCOMP::ACTION other(n);
	this -> _type = other._type;
	this -> _valid = other._valid;
	this -> code = other.code;
	return *this;
}

SECCOMP::ACTION::ACTION() {

	this -> _type = SECCOMP::ACTION::TYPE::KILL;
	this -> _valid = false;
	this -> code = EPERM;
}

SECCOMP::ACTION::ACTION(const SECCOMP::ACTION::TYPE& type) {

	this -> _type = type;
	this -> _valid = true;
	this -> code = EPERM;
}

SECCOMP::ACTION::ACTION(const std::string& name) {

	std::string n = name;
	if ( n == "error" ) n = "errno";
	else if ( n == "SCMP_ACT_ERROR" ) n = "SCMP_ACT_ERRNO";

	if ( auto it = std::find_if(actions.begin(), actions.end(),
		[n](const std::pair<SECCOMP::ACTION::TYPE, SECCOMP::ACTION::MEMBER>& m) {
			return m.second.name == n || m.second.ociname == n;
		}); it != actions.end() && !n.empty()) {
		this -> _type = it -> first;
		this -> _valid = true;
		this -> code = EPERM;
	} else this -> _valid = false;
}

SECCOMP::ACTION::ACTION(const char* name) {

	std::string n(name);
	if ( n == "error" ) n = "errno";
	else if ( n == "SCMP_ACT_ERROR" ) n = "SCMP_ACT_ERRNO";

	if ( auto it = std::find_if(actions.begin(), actions.end(),
		[n](const std::pair<SECCOMP::ACTION::TYPE, SECCOMP::ACTION::MEMBER>& m) {
			return m.second.name == n || m.second.ociname == n;
		}); it != actions.end() && !n.empty()) {
		this -> _type = it -> first;
		this -> _valid = true;
		this -> code = EPERM;
	} else this -> _valid = false;
}

SECCOMP::ACTION::ACTION(const uint32_t value) {

	if ( auto it = std::find_if(actions.begin(), actions.end(),
		[value](const std::pair<SECCOMP::ACTION::TYPE, SECCOMP::ACTION::MEMBER>& m) {
			return m.second.value == value;
		}); it != actions.end()) {
		this -> _type = it -> first;
		this -> _valid = true;
		this -> code = EPERM;
	} else this -> _valid = false;
}

const std::map<SECCOMP::ACTION::TYPE, SECCOMP::ACTION::MEMBER> SECCOMP::ACTION::all() {

	return actions;
}

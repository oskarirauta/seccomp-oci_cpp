#include "seccomp/seccomp.hpp"
#include "seccomp/error.hpp"

static std::map<SECCOMP::ERROR_CODE, std::pair<std::string, bool>> error_descriptions = {
	{ SECCOMP::ERROR_CODE::NO_ERROR, { "no errors", false }},
	{ SECCOMP::ERROR_CODE::IGNORE_EMPTY_SECCOMP, { "ignoring seccomp, empty profile", false }},
	{ SECCOMP::ERROR_CODE::UNSUPPORTED_ARCH, { "unsupported architecture", false }},
	{ SECCOMP::ERROR_CODE::ARCH_MISMATCH, { "seccomp does not allow execution on this architecture", true }},
	{ SECCOMP::ERROR_CODE::OCI_SECCOMP_SECTION_MISSING, { "OCI configuration is missing seccomp section", false }},

	{ SECCOMP::ERROR_CODE::SECCOMP_ALLOCATION_ERROR, { "seccomp failure, memory allocation error", true }},
	{ SECCOMP::ERROR_CODE::FILTER_ALLOCATION_ERROR, { "seccomp filter failure, memory allocation error", true }},
	{ SECCOMP::ERROR_CODE::SET_NO_NEW_PRIVS, { "seccomp failed to set NO_NEW_PRIVS", true }},
	{ SECCOMP::ERROR_CODE::SET_SECCOMP_FILTER, { "seccomp failed to set filter", true }},
	{ SECCOMP::ERROR_CODE::SECCOMP_ALREADY_ENABLED, { "seccomp failed to set filter, one filter is already set", true }},

	{ SECCOMP::ERROR_CODE::OCI_NOT_OBJECT, { "invalid OCI configuration, package is not object", true }},
	{ SECCOMP::ERROR_CODE::OCI_SECCOMP_INVALID, { "invalid OCI seccomp configuration", true }},
	{ SECCOMP::ERROR_CODE::OCI_ANNOTATION_TYPE_ERROR, { "invalid OCI annotation, type error", true }},
	{ SECCOMP::ERROR_CODE::OCI_TYPE_ERROR, { "invalid OCI seccomp configuration, type error", true }},
	{ SECCOMP::ERROR_CODE::OCI_INVALID_SPEC, { "OCI seccomp configuration does not validate", true }},
	{ SECCOMP::ERROR_CODE::OCI_INVALID_CONFIG, { "OCI seccomp configuration syntax error", true }},
	{ SECCOMP::ERROR_CODE::OCI_INVALID_ACTION, { "OCI seccomp configuration error, unsupported action", true }},
	{ SECCOMP::ERROR_CODE::OCI_INVALID_FLAG, { "OCI seccomp configuration error, unsupported flag", true }},
	{ SECCOMP::ERROR_CODE::OCI_INVALID_ARCH, { "OCI seccomp configuration error, unknown architecture", true }},
	{ SECCOMP::ERROR_CODE::OCI_INVALID_SYSCALL, { "OCI seccomp configuration error, unsupported syscall", true }},
	{ SECCOMP::ERROR_CODE::OCI_ARGS_MISSING, { "invalid OCI seccomp configuration, args object requires values index, value and op", true }},
	{ SECCOMP::ERROR_CODE::OCI_UNKNOWN_ARG_OP, { "invalid OCI seccomp configuration, unsupported operator for syscall arguments", true }},
	{ SECCOMP::ERROR_CODE::OCI_MISSING_ACTION, { "OCI seccomp rule is missing action", true }},
	{ SECCOMP::ERROR_CODE::OCI_UNSUPPORTED_FEATURE, { "OCI seccomp feature is not supported", true }},
};

SECCOMP::exception SECCOMP::exception::fatal(bool f) const {

	SECCOMP::exception ex(this -> _e);
	ex._msg = this -> _msg;
	ex._fatal = f;
	return ex;
}

SECCOMP::exception::exception(const SECCOMP::ERROR& e) : std::runtime_error::runtime_error("") {

	this -> _e = e;
	this -> _msg = "";
	this -> _fatal = SECCOMP::ERROR::fatal(e);
}

SECCOMP::exception::exception(const SECCOMP::ERROR_CODE& ec) : std::runtime_error::runtime_error("") {

	this -> _e = SECCOMP::ERROR { .code = ec };
	this -> _msg = "";
	this -> _fatal = SECCOMP::ERROR::fatal(ec);
}

SECCOMP::exception::exception(const SECCOMP::ERROR& e, const std::string& msg) : std::runtime_error::runtime_error("") {

	this -> _e = e;
	this -> _msg = msg;
	this -> _fatal = SECCOMP::ERROR::fatal(e);
}

SECCOMP::exception::exception(const SECCOMP::ERROR_CODE& ec, const std::string& msg) : std::runtime_error::runtime_error("") {

	this -> _e = SECCOMP::ERROR { .code = ec };
	this -> _msg = msg;
	this -> _fatal = SECCOMP::ERROR::fatal(ec);
}

SECCOMP::ERROR& SECCOMP::ERROR::operator =(const SECCOMP::ERROR_CODE& ec) {

	this -> code = ec;
	return *this;
}

SECCOMP::ERROR& SECCOMP::ERROR::operator =(const SECCOMP::ERROR& other) {

	this -> code = other.code;
	return *this;
}

bool SECCOMP::ERROR::operator ==(const SECCOMP::ERROR_CODE& ec) const {

	return this -> code == ec;
}

const std::string SECCOMP::ERROR::describe() const {

	return SECCOMP::ERROR::describe(this -> code);
}

const std::string SECCOMP::ERROR::describe(const SECCOMP::ERROR_CODE& ec) {

	if ( error_descriptions.find(ec) != error_descriptions.end())
		return error_descriptions.at(ec).first;
	else return "unknown error";
}

const bool SECCOMP::ERROR::fatal(const SECCOMP::ERROR_CODE& ec) {

	if ( error_descriptions.find(ec) != error_descriptions.end())
		return error_descriptions.at(ec).second;
	else return true;
}

const bool SECCOMP::ERROR::fatal(const SECCOMP::ERROR& e) {

	if ( error_descriptions.find(e.code) != error_descriptions.end())
		return error_descriptions.at(e.code).second;
	else return true;
}

bool SECCOMP::exception::operator ==(const SECCOMP::ERROR_CODE& ec) const {

	return this -> _e.code == ec;
}

SECCOMP::exception::operator bool() const {

	return !this -> _fatal;
}

const SECCOMP::ERROR_CODE SECCOMP::exception::code() const {

	return this -> _e.code;
}

const bool SECCOMP::exception::is_fatal() const {

	return this -> _fatal;
}

const std::string SECCOMP::exception::msg() const {

	return this -> _msg;
}

const std::string SECCOMP::exception::describe() const {

	return this -> _e.describe();
}

const char* SECCOMP::exception::what() const noexcept {

	return this -> _msg.empty() ? this -> _e.describe().c_str() : this -> _msg.c_str();
}

std::ostream& operator <<(std::ostream& os, const SECCOMP::ERROR& e) {

	os << e.describe();
	return os;
}

std::ostream& operator <<(std::ostream& os, const SECCOMP::exception& e) {

	os << e.what();
	return os;
}

std::ostream& operator <<(std::ostream& os, const SECCOMP::ERROR_CODE& e) {

	os << SECCOMP::ERROR::describe(e);
	return os;
}

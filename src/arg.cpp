#include <algorithm>

namespace audit {
	extern "C" {
		#include <linux/audit.h>
		#include <linux/bpf_common.h>
	}
}

#include "seccomp/seccomp.hpp"
#include "seccomp/arg.hpp"

static const std::map<SECCOMP::ARG::TYPE, SECCOMP::ARG::MEMBER> args = {
	{ SECCOMP::ARG::TYPE::CMP_NE, { .name = "cmp_ne", .ociname = "SCMP_CMP_NE", .value = BPF_JEQ, .inverted = true, .masked = false }},
	{ SECCOMP::ARG::TYPE::CMP_LT, { .name = "cmp_lt", .ociname = "SCMP_CMP_LT", .value = BPF_JGE, .inverted = true, .masked = false }},
	{ SECCOMP::ARG::TYPE::CMP_LE, { .name = "cmp_le", .ociname = "SCMP_CMP_LE", .value = BPF_JGT, .inverted = true, .masked = false }},
	{ SECCOMP::ARG::TYPE::CMP_EQ, { .name = "cmp_eq", .ociname = "SCMP_CMP_EQ", .value = BPF_JEQ, .inverted = false, .masked = false }},
	{ SECCOMP::ARG::TYPE::CMP_GE, { .name = "cmp_ge", .ociname = "SCMP_CMP_GE", .value = BPF_JGE, .inverted = false, .masked = false }},
	{ SECCOMP::ARG::TYPE::CMP_GT, { .name = "cmp_gt", .ociname = "SCMP_CMP_GT", .value = BPF_JGT, .inverted = false, .masked = false }},
	{ SECCOMP::ARG::TYPE::CMP_MASKED_EQ, { .name = "cmp_masked_eq", .ociname = "SCMP_CMP_MASKED_EQ", .value = BPF_JEQ, .inverted = false, .masked = true }},
};

SECCOMP::ARG::TYPE SECCOMP::ARG::type() const {

	return this -> _type;
}

std::string SECCOMP::ARG::name() const {

	return this -> _valid ? args.at(this -> _type).name : "unknown";
}

std::string SECCOMP::ARG::ociname() const {

	return this -> _valid ? args.at(this -> _type).ociname : "";
}

uint32_t SECCOMP::ARG::value() const {

	return this -> _valid ? args.at(this -> _type).value : 0;
}

bool SECCOMP::ARG::valid() const {

	return this -> _valid;
}

bool SECCOMP::ARG::is_inverted() const {

	return this -> _valid ? args.at(this -> _type).inverted : false;
}

bool SECCOMP::ARG::is_masked() const {

	return this -> _valid ? args.at(this -> _type).masked : false;
}

SECCOMP::ARG::operator bool() const {

	return this -> _valid;
}

bool SECCOMP::ARG::operator ==(const SECCOMP::ARG::TYPE& type) const {

	return this -> _valid && this -> _type == type;
}

bool SECCOMP::ARG::operator ==(const std::string& name) const {

	if ( !this -> _valid )
		return false;

        if ( auto it = std::find_if(args.begin(), args.end(),
                [name](const std::pair<SECCOMP::ARG::TYPE, SECCOMP::ARG::MEMBER>& m) {
                        return m.second.name == name || m.second.ociname == name;
                }); it != args.end()) {
		return true;
	}

	return false;
}

bool SECCOMP::ARG::operator ==(const uint32_t value) const {

	if ( auto it = std::find_if(args.begin(), args.end(),
		[value](const std::pair<SECCOMP::ARG::TYPE, SECCOMP::ARG::MEMBER>& m) {
			return m.second.value == value;
		}); it != args.end()) {
		return true;
	}

	return false;
}

SECCOMP::ARG& SECCOMP::ARG::operator =(const SECCOMP::ARG::TYPE& type) {

	this -> _type = type;
	this -> _valid = true;
	return *this;
}

SECCOMP::ARG& SECCOMP::ARG::operator =(const SECCOMP::ARG& other) {

	this -> _type = other._type;
	this -> _valid = other._valid;
	this -> index = other.index;
	this -> value1 = other.value1;
	this -> value2 = other.value2;
	return *this;
}

SECCOMP::ARG& SECCOMP::ARG::operator =(const std::string& name) {

	if ( auto it = std::find_if(args.begin(), args.end(),
		[name](const std::pair<SECCOMP::ARG::TYPE, SECCOMP::ARG::MEMBER>& m) {
			return m.second.name == name || m.second.ociname == name;
		}); it != args.end()) {
		this -> _type = it -> first;
		this -> _valid = true;
	} else this -> _valid = false;

	return *this;
}

SECCOMP::ARG::ARG(const std::string& name) {

	if ( auto it = std::find_if(args.begin(), args.end(),
		[name](const std::pair<SECCOMP::ARG::TYPE, SECCOMP::ARG::MEMBER>& m) {
			return m.second.name == name || m.second.ociname == name;
		}); it != args.end()) {
		this -> _type = it -> first;
		this -> _valid = true;
	} else this -> _valid = false;
}

SECCOMP::ARG::ARG(const char* name) {

	std::string str(name);

	if ( auto it = std::find_if(args.begin(), args.end(),
		[str](const std::pair<SECCOMP::ARG::TYPE, SECCOMP::ARG::MEMBER>& m) {
			return m.second.name == str || m.second.ociname == str;
		}); it != args.end()) {
		this -> _type = it -> first;
		this -> _valid = true;
	} else this -> _valid = false;
}

SECCOMP::ARG::ARG(const uint32_t value) {

	if ( auto it = std::find_if(args.begin(), args.end(),
		[value](const std::pair<SECCOMP::ARG::TYPE, SECCOMP::ARG::MEMBER>& m) {
			return m.second.value == value;
		}); it != args.end()) {
		this -> _type = it -> first;
		this -> _valid = true;
	} else this -> _valid = false;
}

const std::map<SECCOMP::ARG::TYPE, SECCOMP::ARG::MEMBER> SECCOMP::ARG::all() {

	return args;
}

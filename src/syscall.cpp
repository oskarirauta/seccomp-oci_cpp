#include <algorithm>

extern "C" {
	#include <sys/syscall.h>
}

#include "seccomp/seccomp.hpp"
#include "seccomp/syscall.hpp"

#include "./syscall_types.inc"

SECCOMP::SYSCALL::TYPE SECCOMP::SYSCALL::type() const {

	return this -> _type;
}

std::string SECCOMP::SYSCALL::name() const {

	return this -> _valid ? syscalls.at(this -> _type).name : "unknown";
}

std::string SECCOMP::SYSCALL::ociname() const {

	return this -> _valid ? syscalls.at(this -> _type).ociname : "";
}

uint32_t SECCOMP::SYSCALL::value() const {

	return this -> _valid ? syscalls.at(this -> _type).value : 0;
}

bool SECCOMP::SYSCALL::valid() const {

	return this -> _valid;
}

SECCOMP::SYSCALL::operator bool() const {

	return this -> _valid;
}

bool SECCOMP::SYSCALL::operator ==(const SECCOMP::SYSCALL::TYPE& type) const {

	return this -> _valid && this -> _type == type;
}

bool SECCOMP::SYSCALL::operator ==(const std::string& name) const {

	if ( !this -> _valid )
		return false;

        if ( auto it = std::find_if(syscalls.begin(), syscalls.end(),
                [name](const std::pair<SECCOMP::SYSCALL::TYPE, SECCOMP::SYSCALL::MEMBER>& m) {
                        return m.second.name == name || m.second.ociname == name;
                }); it != syscalls.end()) {
		return true;
	}

	return false;
}

bool SECCOMP::SYSCALL::operator ==(const uint32_t value) const {

	if ( auto it = std::find_if(syscalls.begin(), syscalls.end(),
		[value](const std::pair<SECCOMP::SYSCALL::TYPE, SECCOMP::SYSCALL::MEMBER>& m) {
			return m.second.value == value;
		}); it != syscalls.end()) {
		return true;
	}

	return false;
}

SECCOMP::SYSCALL& SECCOMP::SYSCALL::operator =(const SECCOMP::SYSCALL::TYPE& type) {

	this -> _type = type;
	this -> _valid = true;
	return *this;
}

SECCOMP::SYSCALL& SECCOMP::SYSCALL::operator =(const SECCOMP::SYSCALL& other) {

	this -> _type = other._type;
	this -> _valid = other._valid;
	return *this;
}

SECCOMP::SYSCALL& SECCOMP::SYSCALL::operator =(const std::string& name) {

	if ( auto it = std::find_if(syscalls.begin(), syscalls.end(),
		[name](const std::pair<SECCOMP::SYSCALL::TYPE, SECCOMP::SYSCALL::MEMBER>& m) {
			return m.second.name == name || m.second.ociname == name;
		}); it != syscalls.end()) {
		this -> _type = it -> first;
		this -> _valid = true;
	} else this -> _valid = false;

	return *this;
}

SECCOMP::SYSCALL::SYSCALL() {

	this -> _type = SECCOMP::SYSCALL::TYPE::KILL;
	this -> _valid = false;
}

SECCOMP::SYSCALL::SYSCALL(const SECCOMP::SYSCALL::TYPE& type) {

	this -> _type = type;
	this -> _valid = true;
}

SECCOMP::SYSCALL::SYSCALL(const std::string& name) {

	if ( auto it = std::find_if(syscalls.begin(), syscalls.end(),
		[name](const std::pair<SECCOMP::SYSCALL::TYPE, SECCOMP::SYSCALL::MEMBER>& m) {
			return m.second.name == name || m.second.ociname == name;
		}); it != syscalls.end()) {
		this -> _type = it -> first;
		this -> _valid = true;
	} else this -> _valid = false;
}

SECCOMP::SYSCALL::SYSCALL(const char* name) {

	std::string str(name);

	if ( auto it = std::find_if(syscalls.begin(), syscalls.end(),
		[str](const std::pair<SECCOMP::SYSCALL::TYPE, SECCOMP::SYSCALL::MEMBER>& m) {
			return m.second.name == str || m.second.ociname == str;
		}); it != syscalls.end()) {
		this -> _type = it -> first;
		this -> _valid = true;
	} else this -> _valid = false;
}

SECCOMP::SYSCALL::SYSCALL(const uint32_t value) {

	if ( auto it = std::find_if(syscalls.begin(), syscalls.end(),
		[value](const std::pair<SECCOMP::SYSCALL::TYPE, SECCOMP::SYSCALL::MEMBER>& m) {
			return m.second.value == value;
		}); it != syscalls.end()) {
		this -> _type = it -> first;
		this -> _valid = true;
	} else this -> _valid = false;
}

const std::map<SECCOMP::SYSCALL::TYPE, SECCOMP::SYSCALL::MEMBER> SECCOMP::SYSCALL::all() {

	return syscalls;
}

#pragma once

#include <string>
#include <cstdint>
#include <map>

#include "seccomp/seccomp.hpp"

struct SECCOMP::SYSCALL {

	public:

		struct MEMBER {
			std::string name;
			std::string ociname;
			uint32_t value;
		};

		#include "seccomp/types/syscall_names.inc"

		TYPE type() const;
		std::string name() const;
		std::string ociname() const;
		uint32_t value() const;
		bool valid() const;

		operator bool() const;
		bool operator ==(const TYPE& type) const;
		bool operator ==(const std::string& name) const;
		bool operator ==(const uint32_t value) const;

		SYSCALL& operator =(const TYPE& type);
		SYSCALL& operator =(const SYSCALL& other);
		SYSCALL& operator =(const std::string& name);

		SYSCALL();
		SYSCALL(const TYPE& type);
		SYSCALL(const std::string& name);
		SYSCALL(const char* name);
		SYSCALL(const uint32_t value);

		static const std::map<SECCOMP::SYSCALL::TYPE, SECCOMP::SYSCALL::MEMBER> all();

	private:
		TYPE _type = SYSCALL::TYPE::KILL;
		bool _valid = false;

};

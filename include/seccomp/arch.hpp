#pragma once

#include <string>
#include <cstdint>
#include <map>

#include "seccomp/seccomp.hpp"

struct SECCOMP::ARCH {

	public:

		struct MEMBER {
			std::string name;
			std::string ociname;
			uint32_t value;
		};

		enum TYPE {
			X86, X86_64, X32, ARM, ARMEB, AARCH64,
			MIPS, MIPS64, MIPS64N32, MIPSEL, MIPSEL64, MIPSEL64N32,
			PPC, PPC64, PPC64LE, S390, S390X, PARISC, PARISC64
		};

		TYPE type() const;
		std::string name() const;
		std::string ociname() const;
		uint32_t value() const;
		bool valid() const;

		operator bool() const;
		bool operator ==(const TYPE& type) const;
		bool operator ==(const std::string& name) const;
		bool operator ==(const uint32_t value) const;

		ARCH& operator =(const TYPE& type);
		ARCH& operator =(const ARCH& other);
		ARCH& operator =(const std::string& name);

		ARCH(const TYPE& type): _type(type), _valid(true) {}
		ARCH(const std::string& name);
		ARCH(const char* name);
		ARCH(const uint32_t value);

		static const ARCH current();
		static const std::map<SECCOMP::ARCH::TYPE, SECCOMP::ARCH::MEMBER> all();

	private:
		TYPE _type = ARCH::TYPE::X86;
		bool _valid = false;

};

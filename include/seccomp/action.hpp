#pragma once

#include <string>
#include <cstdint>
#include <map>

#include "seccomp/seccomp.hpp"

struct SECCOMP::ACTION {

	public:

		struct MEMBER {
			std::string name;
			std::string ociname;
			uint32_t value;
		};

		enum TYPE {
			KILL, KILLPROCESS, TRAP, ERRNO, TRACE, ALLOW, LOG
		};

		uint32_t code;

		TYPE type() const;
		std::string name() const;
		std::string ociname() const;
		uint32_t value() const;
		bool valid() const;

		operator bool() const;
		bool operator ==(const TYPE& type) const;
		bool operator !=(const TYPE& type) const;
		bool operator ==(const std::string& name) const;
		bool operator !=(const std::string& name) const;
		bool operator ==(const uint32_t value) const;
		bool operator !=(const uint32_t value) const;

		ACTION& operator =(const TYPE& type);
		ACTION& operator =(const ACTION& other);
		ACTION& operator =(const std::string& name);

		ACTION();
		ACTION(const TYPE& type);
		ACTION(const std::string& name);
		ACTION(const char* name);
		ACTION(const uint32_t value);

		static const std::map<SECCOMP::ACTION::TYPE, SECCOMP::ACTION::MEMBER> all();

	private:
		TYPE _type = ACTION::TYPE::KILL;
		bool _valid = false;

};

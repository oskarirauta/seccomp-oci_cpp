#pragma once

#include <string>
#include <cstdint>
#include <map>

#include "seccomp/seccomp.hpp"

struct SECCOMP::ARG {

	public:

		struct MEMBER {
			std::string name;
			std::string ociname;
			uint32_t value;
			bool inverted;
			bool masked;
		};

		enum TYPE {
			CMP_NE, CMP_LT, CMP_LE, CMP_EQ, CMP_GE, CMP_GT, CMP_MASKED_EQ
		};

		uint32_t index;
		uint64_t value1;
		uint64_t value2;

		TYPE type() const;
		std::string name() const;
		std::string ociname() const;
		uint32_t value() const;
		bool valid() const;
		bool is_inverted() const;
		bool is_masked() const;

		operator bool() const;
		bool operator ==(const TYPE& type) const;
		bool operator ==(const std::string& name) const;
		bool operator ==(const uint32_t value) const;

		ARG& operator =(const TYPE& type);
		ARG& operator =(const ARG& other);
		ARG& operator =(const std::string& name);

		ARG(const TYPE& type);
		ARG(const std::string& name);
		ARG(const char* name);
		ARG(const uint32_t value);

		static const std::map<SECCOMP::ARG::TYPE, SECCOMP::ARG::MEMBER> all();

	private:
		TYPE _type = ARG::TYPE::CMP_NE;
		bool _valid = false;

};

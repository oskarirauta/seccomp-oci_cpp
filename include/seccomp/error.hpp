#pragma once
#include <sstream>
#include <string>
#include <map>

#include "seccomp/seccomp.hpp"

struct SECCOMP::ERROR {

	public:
		SECCOMP::ERROR_CODE code = SECCOMP::ERROR_CODE::NO_ERROR;

		ERROR& operator =(const SECCOMP::ERROR_CODE& ec);
		ERROR& operator =(const SECCOMP::ERROR& other);

		bool operator ==(const SECCOMP::ERROR_CODE& ec) const;

        	static const std::string describe(const SECCOMP::ERROR_CODE& ec);
		static const bool fatal(const SECCOMP::ERROR_CODE& ec);
		static const bool fatal(const SECCOMP::ERROR& e);
		const std::string describe() const;

		friend std::ostream& operator <<(std::ostream& os, const SECCOMP::ERROR& e);
};

class SECCOMP::exception : public std::runtime_error {

	private:
		SECCOMP::ERROR _e;
		std::string _msg;
		bool _fatal;

		void init();

	public:

		using std::runtime_error::runtime_error;

		const SECCOMP::ERROR_CODE code() const;
		const bool is_fatal() const;
		const std::string msg() const;
		const std::string describe() const;
		const char* what() const noexcept override;

		exception fatal(bool f = true) const; // override fatality

		bool operator ==(const SECCOMP::ERROR_CODE& ec) const;
		operator bool() const;

		exception(const SECCOMP::ERROR& e);
		exception(const SECCOMP::ERROR_CODE& ec);

		exception(const SECCOMP::ERROR& e, const std::string& msg);
		exception(const SECCOMP::ERROR_CODE& ec, const std::string& msg);

		friend std::ostream& operator <<(std::ostream& os, const JSON::exception& e);
};

std::ostream& operator <<(std::ostream& os, const SECCOMP::ERROR& e);
std::ostream& operator <<(std::ostream& os, const SECCOMP::ERROR_CODE& e);
std::ostream& operator <<(std::ostream& os, const SECCOMP::exception& e);

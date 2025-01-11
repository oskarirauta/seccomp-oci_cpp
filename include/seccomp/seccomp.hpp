#pragma once
#include "json.hpp"

class SECCOMP {

	public:

		enum ERROR_CODE : int {
			NO_ERROR = 0, IGNORE_EMPTY_SECCOMP = 1,
			UNSUPPORTED_ARCH = 2, ARCH_MISMATCH = 3, OCI_SECCOMP_SECTION_MISSING = 4,

			SECCOMP_ALLOCATION_ERROR = 101, FILTER_ALLOCATION_ERROR = 102, SET_NO_NEW_PRIVS = 103, SET_SECCOMP_FILTER = 104,
			SECCOMP_ALREADY_ENABLED = 105,

			OCI_NOT_OBJECT = 201, OCI_SECCOMP_INVALID = 202, OCI_ANNOTATION_TYPE_ERROR = 203, OCI_TYPE_ERROR = 204,
			OCI_INVALID_SPEC = 205, OCI_INVALID_CONFIG = 206, OCI_INVALID_ACTION = 207, OCI_INVALID_FLAG = 208,
			OCI_INVALID_ARCH = 209, OCI_INVALID_SYSCALL = 210, OCI_ARGS_MISSING = 211, OCI_UNKNOWN_ARG_OP = 212,
			OCI_MISSING_ACTION = 213, OCI_UNSUPPORTED_FEATURE = 214

		};

		struct ARCH;
		struct ACTION;
		struct SYSCALL;
		struct RULE;
		struct ARG;
		struct FLAGS;
		struct CONFIG;
		struct ERROR;
		struct FILTER;
		class exception;

		SECCOMP& operator =(const SECCOMP::CONFIG& config);

		SECCOMP::CONFIG config() const;
		void execute();

		static bool is_enabled();
		static bool oci_contains_seccomp(const JSON& json);
		static SECCOMP::CONFIG parse(const JSON& json);

		operator std::string() const;

		SECCOMP();
		SECCOMP(const SECCOMP::CONFIG& config);
		~SECCOMP();

	private:
		CONFIG* _config = nullptr;
		std::string _bpf_code = "";

};

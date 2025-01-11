#include <vector>
#include "json.hpp"
#include "seccomp.hpp"

bool SECCOMP::oci_contains_seccomp(const JSON& json) {

	if ( json.contains("linux") && json["linux"].contains("seccomp"))
		return true;
	else if ( json.contains("seccomp") && json["seccomp"].contains("defaultAction"))
		return true;
	else return json.contains("defaultAction");
}

SECCOMP::CONFIG SECCOMP::parse(const JSON& json) {

	std::vector<std::string> unknown_calls;
	SECCOMP::CONFIG config;
	config.erase();

	if ( json != JSON::OBJECT )
		throw SECCOMP::exception(SECCOMP::ERROR_CODE::OCI_NOT_OBJECT);

	if ( !SECCOMP::oci_contains_seccomp(json)) // not a fatal throw, just ignore seccomp configuration
		throw SECCOMP::exception(SECCOMP::ERROR_CODE::OCI_SECCOMP_SECTION_MISSING).fatal(false);

	JSON j = json;

	if ( j.contains("annotations") && j["annotations"] == JSON::OBJECT &&
		j["annotations"].contains("run.oci.seccomp_fail_unknown_syscall")) {

		if ( j["annotations"]["run.oci.seccomp_fail_unknown_syscall"].convertible_to(JSON::BOOL))
			config.fail_unknown_syscall = j["annotations"]["run.oci.seccomp_fail_unknown_syscall"].to_bool();
		else throw SECCOMP::exception(SECCOMP::ERROR_CODE::OCI_ANNOTATION_TYPE_ERROR,
			"boolean annotation run.oci.seccomp_fail_unknown syscall type error, not valid boolean");
	}

	// validate
	if ( j.contains("linux") && j["linux"].contains("seccomp"))
		j = j["linux"]["seccomp"];
	else if ( j.contains("seccomp") && j["seccomp"].contains("defaultAction"))
		j = j["seccomp"];

	if ( !j.contains("defaultAction"))
		throw SECCOMP::exception(SECCOMP::ERROR_CODE::OCI_SECCOMP_INVALID, "invalid OCI seccomp configuration, missing required defaultAction");
	else if ( j["defaultAction"] != JSON::STRING )
		throw SECCOMP::exception(SECCOMP::ERROR_CODE::OCI_TYPE_ERROR, "invalid OCI seccomp configuration, defaultAction is not a string");

	// defaults
	if ( SECCOMP::ACTION action = j["defaultAction"].to_string(); action )
		config.defaultAction = action;
	else throw SECCOMP::exception(SECCOMP::ERROR_CODE::OCI_INVALID_ACTION, "invalid OCI seccomp defaultAction \"" + j["defaultAction"].to_string() + "\"").fatal();

	if ( j.contains("errnoRet"))
		throw SECCOMP::exception(SECCOMP::ERROR_CODE::OCI_INVALID_SPEC, "OCI seccomp validation failure, errnoRet found in seccomp section, did you mean defaultErrnoRet?");
	else if ( j.contains("defaultErrnoRet")) {

		if ( j["defaultErrnoRet"] != JSON::INT || j["defaultErrnoRet"].to_number() < 0 )
			throw SECCOMP::exception(SECCOMP::ERROR_CODE::OCI_TYPE_ERROR, "invalid OCI seccomp configuration, defaultErrnoRet is not unsigned integer");
		else if ( config.defaultAction != SECCOMP::ACTION::ERRNO )
			throw SECCOMP::exception(SECCOMP::ERROR_CODE::OCI_INVALID_CONFIG, "defaultErrnoRet is allowed only when defaultAction is SCMP_ACT_ERRNO");
		else config.defaultAction.code = (uint32_t)j["defaultErrnoRet"].to_number();

	} else config.defaultAction.code = (uint32_t)EPERM;

	// flags

	if ( j.contains("flags") && j["flags"] == JSON::ARRAY && !j["flags"].empty()) {

		JSON arr = j["flags"];
		for ( auto it = arr.begin(); it != arr.end(); it++ ) {

			if ( it != JSON::STRING )
			throw SECCOMP::exception(SECCOMP::ERROR_CODE::OCI_TYPE_ERROR, "invalid OCI seccomp configuration, flag definitions must be strings");

			std::string flag = it -> to_string();
			if ( flag == "SECCOMP_FILTER_FLAG_TSYNC" ) config.flags += SECCOMP::CONFIG::FLAG::TSYNC;
			else if ( flag == "SECCOMP_FILTER_FLAG_LOG" ) config.flags += SECCOMP::CONFIG::FLAG::LOG;
			else if ( flag == "SECCOMP_FILTER_FLAG_SPEC_ALLOW" ) config.flags += SECCOMP::CONFIG::FLAG::SPEC_ALLOW;
			else if ( flag == "SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV" ) config.flags += SECCOMP::CONFIG::FLAG::WAIT_KILLABLE_RECV;
			else throw SECCOMP::exception(SECCOMP::ERROR_CODE::OCI_INVALID_FLAG, "invalid OCI seccomp configuration, unsupported flag " + flag);
		}

	} else if ( j.contains("flags") && j["flags"] != JSON::ARRAY )
		throw SECCOMP::exception(SECCOMP::ERROR_CODE::OCI_TYPE_ERROR, "invalid OCI seccomp configuration, flags is not array");

	// architectures

	if ( j.contains("architectures") && j["architectures"] == JSON::ARRAY && !j["architectures"].empty()) {

		JSON arr = j["architectures"];
		for ( auto it = arr.begin(); it != arr.end(); it++ ) {

			if ( it != JSON::STRING )
				throw SECCOMP::exception(SECCOMP::ERROR_CODE::OCI_TYPE_ERROR, "invalid OCI seccomp configuration, architecture definitions must be strings");

			if ( SECCOMP::ARCH a = it -> to_string(); a )
				config.architectures.push_back(a);
			else throw SECCOMP::exception(SECCOMP::ERROR_CODE::OCI_INVALID_ARCH, "invalid OCI seccomp configuration, unknown architecture " + it -> to_string());

		}

	} else if ( j.contains("architectures") && j["architectures"] != JSON::ARRAY )
		throw SECCOMP::exception(SECCOMP::ERROR_CODE::OCI_TYPE_ERROR, "invalid OCI seccomp configuration, architectures is not array");

	// rules

	if ( j.contains("syscalls") && j["syscalls"] == JSON::ARRAY ) {

		JSON arr = j["syscalls"];
		for ( auto it = arr.begin(); it != arr.end(); it++ ) {

			if ( it != JSON::OBJECT )
				throw SECCOMP::exception(SECCOMP::ERROR_CODE::OCI_TYPE_ERROR, "invalid OCI seccomp configuration, syscalls child element is not object");

			JSON obj = *it;

			if (( !obj.contains("names") || obj["names"].empty()) && ( !obj.contains("args") || obj["args"].empty()))
				continue;

			SECCOMP::ACTION action = config.defaultAction;

			if ( obj.contains("action") && obj["action"] != JSON::STRING )
				throw SECCOMP::exception(SECCOMP::ERROR_CODE::OCI_TYPE_ERROR, "invalid OCI seccomp configuration, action is not a string");
			else if ( obj.contains("action") && obj["action"] == JSON::STRING ) {
				action = obj["action"].to_string();
				if ( !action )
					throw SECCOMP::exception(SECCOMP::ERROR_CODE::OCI_INVALID_ACTION, "invalid OCI seccomp action \"" + obj["action"].to_string() + "\"");
			} else if ( !obj.contains("action"))
				throw SECCOMP::exception(SECCOMP::ERROR_CODE::OCI_MISSING_ACTION);

			if ( obj.contains("errnoRet") && action != SECCOMP::ACTION::ERRNO )
				throw SECCOMP::exception(SECCOMP::ERROR_CODE::OCI_INVALID_CONFIG, "errnoRet is allowed only when action is SCMP_ACT_ERRNO");
			else if ( obj.contains("errnoRet") && ( obj["errnoRet"] != JSON::INT || obj["errnoRet"].to_number() < 0 ))
				throw SECCOMP::exception(SECCOMP::ERROR_CODE::OCI_TYPE_ERROR, "invalid OCI seccomp configuration, errnoRet is not unsigned integer");
			else if ( obj.contains("errnoRet") && obj["errnoRet"] == JSON::INT )
				action.code = obj["errnoRet"].to_number();

			SECCOMP::RULE rule = { .action = action };

			if ( obj.contains("names") && obj["names"] != JSON::ARRAY )
				throw SECCOMP::exception(SECCOMP::ERROR_CODE::OCI_TYPE_ERROR, "invalid OCI seccomp configuration, syscall names section is not array");
			else if ( obj.contains("names") && obj["names"] == JSON::ARRAY && !obj["names"].empty()) {

				JSON arr2 = obj["names"];

				for ( auto it2 = arr2.begin(); it2 != arr2.end(); it2++ ) {

					if ( it2 != JSON::STRING )
						throw SECCOMP::exception(SECCOMP::ERROR_CODE::OCI_TYPE_ERROR, "invalid OCI seccomp configuration, syscall name definitions must be strings");

					SECCOMP::SYSCALL syscall = it2 -> to_string();
					if ( !syscall && !config.fail_unknown_syscall ) {
						unknown_calls.push_back(it2 -> to_string());
						continue;
					} else if ( !syscall )
						throw SECCOMP::exception(SECCOMP::ERROR_CODE::OCI_INVALID_SYSCALL, "invalid OCI seccomp configuration, unsupported syscall \"" + it2 -> to_string() + "\"");
					else rule.syscalls.push_back(syscall);
				}
			}

			if ( obj.contains("args") && obj["args"] != JSON::ARRAY )
				throw SECCOMP::exception(SECCOMP::ERROR_CODE::OCI_TYPE_ERROR, "invalid OCI seccomp configuration, args section is not array");
			else if ( obj.contains("args") && obj["args"] == JSON::ARRAY && !obj["args"].empty()) {

				JSON arr3 = obj["args"];

				for ( auto it3 = arr3.begin(); it3 != arr3.end(); it3++ ) {

					JSON obj2 = *it3;

					if ( obj2 != JSON::OBJECT )
						throw SECCOMP::exception(SECCOMP::ERROR_CODE::OCI_TYPE_ERROR, "invalid OCI seccomp configuration, syscall's args child is not object");
					else if ( !obj2.contains("index") || !obj2.contains("value") || !obj2.contains("op"))
						throw SECCOMP::exception(SECCOMP::ERROR_CODE::OCI_ARGS_MISSING);
					else if ( obj2.contains("index") && ( obj2["index"] != JSON::INT || obj2["index"].to_number() < 0 ))
						throw SECCOMP::exception(SECCOMP::ERROR_CODE::OCI_TYPE_ERROR, "invalid OCI seccomp configuration, args index is not unsigned integer");
					else if ( obj2.contains("value") && ( obj2["value"] != JSON::INT || obj2["value"].to_number() < 0 ))
						throw SECCOMP::exception(SECCOMP::ERROR_CODE::OCI_TYPE_ERROR, "invalid OCI seccomp configuration, args value is not unsigned integer");
					else if ( obj2.contains("op") && obj2["op"] != JSON::STRING )
						throw SECCOMP::exception(SECCOMP::ERROR_CODE::OCI_TYPE_ERROR, "invalid OCI seccomp configuration, args op is not string");
					else if ( obj2.contains("valueTwo") && ( obj2["valueTwo"] != JSON::INT || obj2["valueTwo"].to_number() < 0 ))
						throw SECCOMP::exception(SECCOMP::ERROR_CODE::OCI_TYPE_ERROR, "invalid OCI seccomp configuration, args valueTwo is not unsigned integer");

					SECCOMP::ARG arg = obj2["op"].to_string();
					if ( !arg )
						throw SECCOMP::exception(SECCOMP::ERROR_CODE::OCI_UNKNOWN_ARG_OP, "invalid OCI seccomp configuration, unsupported operator \"" + obj2["op"].to_string() + "\" for syscall arguments");

					arg.index = (uint32_t)obj2["index"].to_number();
					arg.value1 = (uint64_t)obj2["value"].to_number();
					arg.value2 = obj2.contains("valueTwo") ? (uint64_t)obj2["valueTwo"].to_number() : (uint64_t)0;

					rule.args.push_back(arg);
				}
			}

			if ( !rule.syscalls.empty())
				config.rules.push_back(rule);
		}

	} else if ( j.contains("syscalls") && j["syscalls"] != JSON::ARRAY )
		throw SECCOMP::exception(SECCOMP::ERROR_CODE::OCI_TYPE_ERROR, "invalid OCI seccomp configuration, syscalls is not array");

	if ( !unknown_calls.empty()) { // report unknown syscalls to stderr if tolerance is allowed

		std::cerr << "unknown syscalls:";

		for ( auto sc : unknown_calls )
			std::cerr << " " << sc;
		std::cerr << std::endl;
	}

	return config;
}

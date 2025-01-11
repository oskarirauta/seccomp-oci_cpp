#include <iostream>
#include <fstream>
#include <vector>
#include <unistd.h>

#include "json.hpp"
#include "seccomp.hpp"

int main(int argc, char** argv) {

	std::cout << "this is a seccomp test.\n" << std::endl;

	std::ifstream ifd("seccomp.json", std::ios::in);
	JSON json;
	SECCOMP::CONFIG cfg;

	try {
		json = JSON::load(ifd);
		//std::cout << "json dump:\n" << json << std::endl;
	} catch ( const JSON::exception& e ) {
		std::cerr << "failed to read or parse seccomp config from file seccomp.json\nerror: " << e.what() << std::endl;
		return 1;
	}

	if ( !SECCOMP::oci_contains_seccomp(json)) {
		std::cerr << "seccomp configuration not found from json:\n" << json << std::endl;
		return 1;
	}

	try {
		cfg = SECCOMP::parse(json);
		std::cout << cfg << std::endl;
	} catch ( const SECCOMP::exception& e ) {
		std::cerr << "failed to parse seccomp configuration, error: " << e.what() << std::endl;
		return 1;
	}

	SECCOMP seccomp(cfg);

	try {
		std::cout << "\ninstalling seccomp filter" << std::endl;
		seccomp.execute();

		std::cout << "\ngenerated bpf program:\n" << seccomp << "\n" << std::endl;
		std::cout << "seccomp is " << ( SECCOMP::is_enabled() ? "enabled" : "not enabled" ) << "\nexecuting shell" << std::endl;

	} catch ( const SECCOMP::exception& e ) {

		if ( e.is_fatal()) {
			std::cerr << "\nfailed to install seccomp filter\nfatal error: " << e.what() << std::endl;
			return 1;
		}

		std::cout << "non-fatal error while installing seccomp filter: " << e.what() << std::endl;
		if ( SECCOMP::is_enabled())
			std::cout << "\ngenerated bpf program:\n" << seccomp << "\n" << std::endl;

		std::cout << "seccomp is " << ( SECCOMP::is_enabled() ? "enabled" : "not enabled" ) << "\nexecuting shell" << std::endl;
	}

	// execute shell

	std::vector<char*> cmd = { (char*)"/bin/sh", nullptr };
	::execvp(cmd[0], cmd.data());

	return 0;
}

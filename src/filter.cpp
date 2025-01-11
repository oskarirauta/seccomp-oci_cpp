#include <cstdio>
#include <sstream>
#include <iomanip>
#include "seccomp/seccomp.hpp"
#include "seccomp/error.hpp"
#include "seccomp/filter.hpp"

size_t SECCOMP::FILTER::size() const {

	return this -> _filters.size();
}

sock_filter* SECCOMP::FILTER::filter() {

	return this -> _filters.data();
}

void SECCOMP::FILTER::clear() {

	this -> _filters.clear();
}

void SECCOMP::FILTER::erase() {

	this -> clear();
}

void SECCOMP::FILTER::add(const sock_filter filter) {

	this -> _filters.push_back(filter);
}

SECCOMP::FILTER::operator std::string() const {

	size_t idx = 0;
	std::stringstream ret;

	ret << " [idx]\tcode\t jt\t jf\tk";

	idx = 0;
	for ( auto it = this -> _filters.begin(); it != this -> _filters.end(); it++ ) {

		ret << "\n [" << std::setfill('0') << std::setw(3) << idx << "]\t";
		ret << std::setfill('0') << std::setw(4) << it -> code << "\t";
		ret << std::setfill(' ') << std::setw(3) << (int)it -> jt << "\t";
		ret << std::setfill(' ') << std::setw(3) << (int)it -> jf << "\t";
		ret << std::setfill('0') << std::setw(8) << std::hex << it -> k;
		idx++;
	}

	return ret.str();
}

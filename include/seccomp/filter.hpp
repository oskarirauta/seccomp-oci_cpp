#pragma once

#include <string>
#include <vector>
#include <linux/filter.h>
#include "seccomp/seccomp.hpp"

struct SECCOMP::FILTER {

	public:

		void clear();
		void erase();
		size_t size() const;
		void add(const sock_filter filter);
		sock_filter* filter();
		operator std::string() const;

	private:
		std::vector<sock_filter> _filters = {};

};


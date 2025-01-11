#pragma once
#include <string>
#include <vector>
#include <iostream>
#include "featureset.hpp"
#include "seccomp/seccomp.hpp"
#include "seccomp/arch.hpp"
#include "seccomp/syscall.hpp"
#include "seccomp/action.hpp"
#include "seccomp/rule.hpp"
#include "seccomp/arg.hpp"

struct SECCOMP::CONFIG {

	public:

		enum MODE {
			FILTER, STRICT
		};

		enum FLAG {
			TSYNC, LOG, SPEC_ALLOW, WAIT_KILLABLE_RECV
		};

		SECCOMP::ACTION defaultAction = SECCOMP::ACTION::TYPE::KILL;
		FeatureSet<FLAG> flags = {};
		std::vector<SECCOMP::ARCH> architectures = {};
		std::vector<SECCOMP::RULE> rules = {};
		MODE mode = SECCOMP::CONFIG::MODE::FILTER;
		bool fail_unknown_syscall = true;

		operator std::string() const;

		void clear();
		void erase();
		int seccomp_mode();
		int seccomp_syscall_mode();
		int flags_value();
		bool empty() const;
};

std::ostream& operator <<(std::ostream& os, const SECCOMP::CONFIG& config);
std::ostream& operator <<(std::ostream& os, const SECCOMP::CONFIG* config);

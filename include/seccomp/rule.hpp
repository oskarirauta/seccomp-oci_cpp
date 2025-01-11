#pragma once
#include <vector>
#include <linux/types.h>
#include "seccomp/seccomp.hpp"
#include "seccomp/syscall.hpp"
#include "seccomp/action.hpp"

struct SECCOMP::RULE {

	public:

		struct SC_ELEMENT {
			size_t idx, deny_idx, allow_idx;
			__u32 sc;
		};

		struct ARG_ELEMENT {
			size_t idx, deny_idx, allow_idx;
			__u32 offset;
			bool inverted;
			bool masked;
			__u32 nr;
			uint64_t value1;
			uint64_t value2;
		};

		using for_each_syscall_function = std::function<void(SC_ELEMENT&)>;
		using for_each_arg_function = std::function<void(ARG_ELEMENT&)>;

		std::vector<SECCOMP::SYSCALL> syscalls = {};
		std::vector<SECCOMP::ARG> args = {};
		SECCOMP::ACTION action = SECCOMP::ACTION::TYPE::KILL;

		size_t syscalls_size() const;
		size_t args_size() const;
		size_t size() const;
		bool empty() const;

		void for_each_syscall(const for_each_syscall_function lambda) const;
		void for_each_arg(const for_each_arg_function lambda) const;
};

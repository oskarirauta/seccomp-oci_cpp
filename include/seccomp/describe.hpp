#pragma once
#include <iostream>
#include "seccomp/config.hpp"
#include "seccomp/action.hpp"
#include "seccomp/syscall.hpp"
#include "seccomp/arch.hpp"
#include "seccomp/arg.hpp"
#include "seccomp/filter.hpp"
#include "seccomp/seccomp.hpp"

std::ostream& operator <<(std::ostream& os, const SECCOMP::CONFIG::MODE& mode);
std::ostream& operator <<(std::ostream& os, const SECCOMP::CONFIG::FLAG& flag);
std::ostream& operator <<(std::ostream& os, const SECCOMP::ACTION& action);
std::ostream& operator <<(std::ostream& os, const SECCOMP::ARCH& arch);
std::ostream& operator <<(std::ostream& os, const SECCOMP::SYSCALL& syscall);
std::ostream& operator <<(std::ostream& os, const SECCOMP::ARG& arg);

std::ostream& operator <<(std::ostream& os, const SECCOMP::FILTER& filter);
std::ostream& operator <<(std::ostream& os, const SECCOMP::FILTER* filter);

std::ostream& operator <<(std::ostream& os, const SECCOMP& seccomp);
std::ostream& operator <<(std::ostream& os, const SECCOMP* seccomp);

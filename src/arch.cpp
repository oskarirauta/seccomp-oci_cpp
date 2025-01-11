#include <algorithm>

namespace audit {
	extern "C" {
		#include <linux/audit.h>
	}
}

#include "seccomp/seccomp.hpp"
#include "seccomp/error.hpp"
#include "seccomp/arch.hpp"

static const std::map<SECCOMP::ARCH::TYPE, SECCOMP::ARCH::MEMBER> archs = {
	{ SECCOMP::ARCH::TYPE::X86, { .name = "x86", .ociname = "SCMP_ARCH_X86", .value = AUDIT_ARCH_I386 }},
	{ SECCOMP::ARCH::TYPE::X86_64, { .name = "x86_64", .ociname = "SCMP_ARCH_X86_64", .value = AUDIT_ARCH_X86_64 }},
	/* 32-bit userland on 64-bit kernel is not supported yet */
	{ SECCOMP::ARCH::TYPE::X32, { .name = "x32", .ociname = "SCMP_ARCH_X32", .value = AUDIT_ARCH_X86_64 }},
	{ SECCOMP::ARCH::TYPE::ARM, { .name = "arm", .ociname = "SCMP_ARCH_ARM", .value = AUDIT_ARCH_ARM }},
	{ SECCOMP::ARCH::TYPE::ARMEB, { .name = "armeb", .ociname = "SCMP_ARCH_ARMEB", .value = AUDIT_ARCH_ARMEB }},
	{ SECCOMP::ARCH::TYPE::AARCH64, { .name = "aarch64", .ociname = "SCMP_ARCH_AARCH64", .value = AUDIT_ARCH_AARCH64 }},
	{ SECCOMP::ARCH::TYPE::MIPS, { .name = "mips", .ociname = "SCMP_ARCH_MIPS", .value = AUDIT_ARCH_MIPS }},
	{ SECCOMP::ARCH::TYPE::MIPS64, { .name = "mips64", .ociname = "SCMP_ARCH_MIPS64", .value = AUDIT_ARCH_MIPS64 }},
	{ SECCOMP::ARCH::TYPE::MIPS64N32, { .name = "mips64n32", .ociname = "SCMP_ARCH_MIPS64N32", .value = AUDIT_ARCH_MIPS64N32 }},
	{ SECCOMP::ARCH::TYPE::MIPSEL, { .name = "mipsel", .ociname = "SCMP_ARCH_MIPSEL", .value = AUDIT_ARCH_MIPSEL }},
	{ SECCOMP::ARCH::TYPE::MIPSEL64, { .name = "mipsel64", .ociname = "SCMP_ARCH_MIPSEL64", .value = AUDIT_ARCH_MIPSEL64 }},
	{ SECCOMP::ARCH::TYPE::MIPSEL64N32, { .name = "mipsel64n32", .ociname = "SCMP_ARCH_MIPSEL64N32", .value = AUDIT_ARCH_MIPSEL64N32 }},
	{ SECCOMP::ARCH::TYPE::PPC, { .name = "ppc", .ociname = "SCMP_ARCH_PPC", .value = AUDIT_ARCH_PPC }},
	{ SECCOMP::ARCH::TYPE::PPC64, { .name = "ppc64", .ociname = "SCMP_ARCH_PPC64", .value = AUDIT_ARCH_PPC64 }},
	{ SECCOMP::ARCH::TYPE::PPC64LE, { .name = "ppc64le", .ociname = "SCMP_ARCH_PPC64LE", .value = AUDIT_ARCH_PPC64LE }},
	{ SECCOMP::ARCH::TYPE::S390, { .name = "s390", .ociname = "SCMP_ARCH_S390", .value = AUDIT_ARCH_S390 }},
	{ SECCOMP::ARCH::TYPE::S390X, { .name = "s390x", .ociname = "SCMP_ARCH_S390X", .value = AUDIT_ARCH_S390X }},
	{ SECCOMP::ARCH::TYPE::PARISC, { .name = "parisc", .ociname = "SCMP_ARCH_PARISC", .value = AUDIT_ARCH_PARISC }},
	{ SECCOMP::ARCH::TYPE::PARISC64, { .name = "parisc64", .ociname = "SCMP_ARCH_PARISC64", .value = AUDIT_ARCH_PARISC64 }},
};

SECCOMP::ARCH::TYPE SECCOMP::ARCH::type() const {

	return this -> _type;
}

std::string SECCOMP::ARCH::name() const {

	return this -> _valid ? archs.at(this -> _type).name : "unknown";
}

std::string SECCOMP::ARCH::ociname() const {

	return this -> _valid ? archs.at(this -> _type).ociname : "";
}

uint32_t SECCOMP::ARCH::value() const {

	return this -> _valid ? archs.at(this -> _type).value : 0;
}

bool SECCOMP::ARCH::valid() const {

	return this -> _valid;
}

SECCOMP::ARCH::operator bool() const {

	return this -> _valid;
}

bool SECCOMP::ARCH::operator ==(const SECCOMP::ARCH::TYPE& type) const {

	return this -> _valid && this -> _type == type;
}

bool SECCOMP::ARCH::operator ==(const std::string& name) const {

	if ( !this -> _valid )
		return false;

        if ( auto it = std::find_if(archs.begin(), archs.end(),
                [name](const std::pair<SECCOMP::ARCH::TYPE, SECCOMP::ARCH::MEMBER>& m) {
                        return m.second.name == name || m.second.ociname == name;
                }); it != archs.end()) {
		return true;
	}

	return false;
}

bool SECCOMP::ARCH::operator ==(const uint32_t value) const {

	if ( auto it = std::find_if(archs.begin(), archs.end(),
		[value](const std::pair<SECCOMP::ARCH::TYPE, SECCOMP::ARCH::MEMBER>& m) {
			return m.second.value == value;
		}); it != archs.end()) {
		return true;
	}

	return false;
}

SECCOMP::ARCH& SECCOMP::ARCH::operator =(const SECCOMP::ARCH::TYPE& type) {

	this -> _type = type;
	this -> _valid = true;
	return *this;
}

SECCOMP::ARCH& SECCOMP::ARCH::operator =(const SECCOMP::ARCH& other) {

	this -> _type = other._type;
	this -> _valid = other._valid;
	return *this;
}

SECCOMP::ARCH& SECCOMP::ARCH::operator =(const std::string& name) {

	if ( auto it = std::find_if(archs.begin(), archs.end(),
		[name](const std::pair<SECCOMP::ARCH::TYPE, SECCOMP::ARCH::MEMBER>& m) {
			return m.second.name == name || m.second.ociname == name;
		}); it != archs.end()) {
		this -> _type = it -> first;
		this -> _valid = true;
	} else this -> _valid = false;

	return *this;
}

const SECCOMP::ARCH SECCOMP::ARCH::current() {

#if defined(__aarch64__)
	uint32_t ARCH_NR = (uint32_t)AUDIT_ARCH_AARCH64;
#elif defined(__amd64__)
	uint32_t ARCH_NR = (uint32_t)AUDIT_ARCH_X86_64;
#elif defined(__arm__) && (defined(__ARM_EABI__) || defined(__thumb__))
# if __BYTE_ORDER == __LITTLE_ENDIAN
	uint32_t ARCH_NR = (uint32_t)AUDIT_ARCH_ARM;
# else
	uint32_t ARCH_NR = (uint32_t)AUDIT_ARCH_ARMEB;
# endif
#elif defined(__i386__)
	uint32_t ARCH_NR = (uint32_t)AUDIT_ARCH_I386;
#elif defined(__mips__) && defined(__MIPSEB__) && _MIPS_SIM == _MIPS_SIM_ABI32
	uint32_t ARCH_NR = (uint32_t)AUDIT_ARCH_MIPS64;
#elif defined(__mips__) && defined(__MIPSEL__) && _MIPS_SIM == _MIPS_SIM_ABI32
	uint32_t ARCH_NR = (uint32_t)AUDIT_ARCH_MIPSEL;
#elif defined(__mips__) && defined(__MIPSEB__) && _MIPS_SIM == _MIPS_SIM_ABI64
	uint32_t ARCH_NR = (uint32_t)AUDIT_ARCH_MIPS64;
#elif defined(__mips__) && defined(__MIPSEL__) && _MIPS_SIM == _MIPS_SIM_ABI64
	uint32_t ARCH_NR = (uint32_t)AUDIT_ARCH_MIPSEL64;
#elif defined(__mips__) && defined(__MIPSEB__) && _MIPS_SIM == _MIPS_SIM_NABI32
	uint32_t ARCH_NR = (uint32_t)AUDIT_ARCH_MIPS64N32;
#elif defined(__mips__) && defined(__MIPSEL__) && _MIPS_SIM == _MIPS_SIM_NABI32
	uint32_t ARCH_NR = (uint32_t)AUDIT_ARCH_MIPSEL64N32;
#elif defined(__mips__)
# if __BYTE_ORDER == __LITTLE_ENDIAN
	uint32_t ARCH_NR = (uint32_t)AUDIT_ARCH_MIPSEL;
# else
	uint32_t ARCH_NR = (uint32_t)AUDIT_ARCH_MIPS;
# endif
#elif defined(__hppa64__) /* from libseccomp: hppa64 must be checked before hppa */
	uint32_t ARCH_NR = (uint32_t)AUDIT_ARCH_PARISC64;
#elif defined(__hppa__)
	uint32_t ARCH_NR = (uint32_t)AUDIT_ARCH_PARISC;
#elif defined(__PPC64__)
# if defined(__BIG_ENDIAN__)
	uint32_t ARCH_NR = (uint32_t)AUDIT_ARCH_PPC64;
# else
	uint32_t ARCH_NR = (uint32_t)AUDIT_ARCH_PPC64LE;
# endif
#elif defined(__PPC__)
	uint32_t ARCH_NR = (uint32_t)AUDIT_ARCH_PPC;
#elif __s390x__ /* from libseccomp: s390x must be checked before s390 */
	uint32_t ARCH_NR = (uint32_t)AUDIT_ARCH_S390X;
#elif __s390__
	uint32_t ARCH_NR = (uint32_t)AUDIT_ARCH_S390;

#else
	throw SECCOMP::exception(SECCOMP::ERROR_CODE::UNSUPPORTED_ARCH);
#endif

	return SECCOMP::ARCH(ARCH_NR);
}

SECCOMP::ARCH::ARCH(const std::string& name) {

	if ( auto it = std::find_if(archs.begin(), archs.end(),
		[name](const std::pair<SECCOMP::ARCH::TYPE, SECCOMP::ARCH::MEMBER>& m) {
			return m.second.name == name || m.second.ociname == name;
		}); it != archs.end()) {
		this -> _type = it -> first;
		this -> _valid = true;
	} else this -> _valid = false;
}

SECCOMP::ARCH::ARCH(const char* name) {

	std::string str(name);

	if ( auto it = std::find_if(archs.begin(), archs.end(),
		[str](const std::pair<SECCOMP::ARCH::TYPE, SECCOMP::ARCH::MEMBER>& m) {
			return m.second.name == str || m.second.ociname == str;
		}); it != archs.end()) {
		this -> _type = it -> first;
		this -> _valid = true;
	} else this -> _valid = false;
}

SECCOMP::ARCH::ARCH(const uint32_t value) {

	if ( auto it = std::find_if(archs.begin(), archs.end(),
		[value](const std::pair<SECCOMP::ARCH::TYPE, SECCOMP::ARCH::MEMBER>& m) {
			return m.second.value == value;
		}); it != archs.end()) {
		this -> _type = it -> first;
		this -> _valid = true;
	} else this -> _valid = false;
}

const std::map<SECCOMP::ARCH::TYPE, SECCOMP::ARCH::MEMBER> SECCOMP::ARCH::all() {

	return archs;
}

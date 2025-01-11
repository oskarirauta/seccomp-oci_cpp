#include <iostream>
#include <cstring>
#include <sys/personality.h>

#if defined(PERSONA)
const unsigned long persona = PERSONA;
#else
const unsigned long persona = 4294967295;
#endif

int main(int argc, char **argv) {

	std::cout << "attempting to set persona to " << persona << std::endl;
	int ret = ::personality(persona);

	if ( ret == -1 )
		std::cout << "failed, error: " << strerror(errno) << std::endl;
	else
		std::cout << "success, previous persona was: " << ret << std::endl;

	return 0;
}

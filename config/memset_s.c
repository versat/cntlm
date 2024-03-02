#define __STDC_WANT_LIB_EXT1__ 1
#include <string.h>

#define BUFFER_SIZE 16

int main(int argc, char **argv) {
	int retval;
	char buffer[BUFFER_SIZE] = {0};

	retval = memset_s(buffer, BUFFER_SIZE, 'a', BUFFER_SIZE);

	return !retval;
}

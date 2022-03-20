#include <string.h>

#define BUFFER_SIZE 16

int main(int argc, char **argv) {
	int retval;
	char buffer[BUFFER_SIZE] = {0};

	retval = strlcpy(buffer, "hello", BUFFER_SIZE);

	return !!retval;
}

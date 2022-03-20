#include <string.h>

int main(int argc, char **argv) {
	int retval;
	int size = 8;
	char buffer[size] = {0};

	retval = strlcpy(buffer, "hello", size);

	return !!retval;
}

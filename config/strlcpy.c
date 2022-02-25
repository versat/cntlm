#include <string.h>

int main(int argc, char **argv) {
	int retval;
	int size = 8;
	char buffer[size];

	retval = strlcpy(buffer, "hello", size);

	return !!retval;
}

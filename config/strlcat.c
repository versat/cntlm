#include <string.h>

int main(int argc, char **argv) {
	int retval;
	int size = 16;
	char buffer[size] = {0};

	retval = strlcat(buffer, "hello", size);
	retval = strlcat(buffer, " world!", size);

	return !!retval;
}

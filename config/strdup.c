#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
	int retval;
	char * pstrdup;

	pstrdup = strdup("hello");
	retval = !strcmp("hello", pstrdup);
	free(pstrdup);

	return retval;
}

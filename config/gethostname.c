#include <unistd.h>
#include <string.h>
#include <stdio.h>

int main(int argc, char **argv) {
	char tmp[300];

	memset(tmp, 0, sizeof(tmp));
	gethostname(tmp, sizeof(tmp)-1);
	if (strlen(tmp))
		printf("%s", tmp);

	return !(!strlen(tmp));
}

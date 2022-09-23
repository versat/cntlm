#include <stdio.h>
#include <stdint.h>

const uint8_t num[] = { 0xEF, 0xBE };

/*
 * RC: 1 = LE, 0 = BE
 */
int main(int argc, char **argv) {
	int rc;

	rc = (*((uint16_t *)num) == 0xBEEF);
	printf("%s\n", rc ? "little endian" : "big endian");

	return rc;
}

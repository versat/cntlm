#include <stdlib.h>

int main(int argc, char **argv) {
    int random_number;
    
    arc4random_buf(&random_number, sizeof(random_number));

	return 1;
}

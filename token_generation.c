#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <openssl/bn.h>
#include <openssl/rand.h>
#include <termios.h>

#define NONCE_BYTES 16
#define ELECTION_ID "AUA_policy_change_vote_2025"

static void wait_for_enter(const char *prompt) {
	struct termios oldt, newt;
	printf("%s", prompt);
	fflush(stdout);

	if(tcgetattr(STDIN_FILENO, &oldt) == -1) {
		int c;
		while((c = getchar()) != '\n' && c != '\r' && c != EOF) { }
		return;
	}

	newt = oldt;
	newt.c_lflag &= ~(ICANON | ECHO);
	tcsetattr(STDIN_FILENO, TCSANOW, & newt);

	int c;
	while((c = getchar()) != '\n' && c != '\r' && c != EOF) { }

	tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
	printf("\n");
}

static int seed_from_dev_random(size_t bytes) {
	unsigned char buf[64];
	if(bytes > sizeof(buf)) {
		bytes = sizeof(buf);
	}

	FILE *f = fopen("/dev/random", "rb");
	if(!f) {
		perror("fopen /dev/random");
		return 0;
	}

	size_t r = fread(buf, 1, bytes, f);
	fclose(f);

	if(r != bytes) {
		fprintf(stderr, "Not enough entropy from /dev/random\n");
		return 0;
	}

	RAND_add(buf, (int)bytes, (double)bytes);

	for(size_t i = 0; i < bytes; i++) {
		buf[i] = 0;
	}
	return 1;
}

static int init_random(void) {
	if(RAND_poll() != 1) {
		fprintf(stderr, "RAND_poll failed\n");
		return 0;
	}

	printf(" Collecting user entropy\n");
	printf("Please move your mouse randomly for a few seconds, then press Enter\n");
	wait_for_enter(">");

	if(!seed_from_dev_random(32)) {
		fprintf(stderr, "Warning: could not strengthen RNG from /dev/random.\n");
	}

	if(RAND_status() != 1) {
		fprintf(stderr, "CSPRNG not properly seeded\n");
		return 0;
	}

	printf("User RNG seeded.\n\n");
	return 1;
}

int main(void) {
	printf("=== Token Generation RNG Test ===\n\n");

	if (!init_random()) {
		fprintf(stderr, "Failed to initialize RNG\n");
		return 1;
	}

	printf("Testing RNG by generating some random bytes:\n");
	unsigned char test_bytes[32];
	if (RAND_bytes(test_bytes, sizeof(test_bytes)) != 1) {
		fprintf(stderr, "RAND_bytes failed\n");
		return 1;
	}

	printf("Random bytes (hex): ");
	for (size_t i = 0; i < sizeof(test_bytes); i++) {
		printf("%02x", test_bytes[i]);
	}
	printf("\n\n");

	printf("RNG test successful!\n");
	return 0;
}

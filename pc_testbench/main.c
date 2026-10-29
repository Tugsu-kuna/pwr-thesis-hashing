#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "sha256.h"

// The official NIST Known Answer Test (KAT) for the string "abc"
const char *EXPECTED_HASH = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

void print_hex(uint8_t *data, size_t len, char *out_str) {
    for (size_t i = 0; i < len; ++i) {
        sprintf(out_str + (i * 2), "%02x", data[i]);
    }
    out_str[len * 2] = '\0';
}

int main(void) {
    printf("--- Hashing Algorithms Testbench ---\n");

    // 1. Prepare test vector
    uint8_t text[] = "abc";
    uint8_t hash[32];
    char hash_str[65];

    // 2. Hash it using our bare-metal implementation
    SHA256_CTX ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, text, strlen((char*)text));
    sha256_final(&ctx, hash);

    // 3. Format and verify
    print_hex(hash, 32, hash_str);
    printf("Input    : %s\n", text);
    printf("Computed : %s\n", hash_str);
    printf("Expected : %s\n", EXPECTED_HASH);

    if (strcmp(hash_str, EXPECTED_HASH) == 0) {
        printf("\n[SUCCESS] SHA-256 implementation passes NIST vector!\n");
    } else {
        printf("\n[FAIL] Output does not match.\n");
    }

    return 0;
}

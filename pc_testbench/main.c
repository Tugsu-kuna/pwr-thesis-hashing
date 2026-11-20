#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "blake2s.h"

// The official NIST Known Answer Test (KAT) for the string "abc"
//const char *EXPECTED_HASH = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
// expected hash changed to accomodate to blake2s tho
const char *EXPECTED_BLAKE2S = "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982";
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
    // changed methods too 
    BLAKE2S_CTX ctx;
    blake2s_init(&ctx);
    blake2s_update(&ctx, text, strlen((char*)text));
    blake2s_final(&ctx, hash);

    // 3. Format and verify
    print_hex(hash, 32, hash_str);
    printf("Input    : %s\n", text);
    printf("Computed : %s\n", hash_str);
    printf("Expected : %s\n", EXPECTED_BLAKE2S);

    if (strcmp(hash_str, EXPECTED_BLAKE2S) == 0) {
        printf("\n[SUCCESS] Blake2s implementation passes NIST vector!\n");
    } else {
        printf("\n[FAIL] Output does not match.\n");
    }

    return 0;
}

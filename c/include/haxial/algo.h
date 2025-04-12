#pragma once
#include "cfg.h"

#include <stdint.h>

enum
{
	HX_OK,
	HX_ALIGN,
	HX_LENGTH
};

#ifdef __cplusplus
extern "C"
{
#endif // __cplusplus

/**
 * @brief Cryptographic random data generator using a mixing algorithm with MD5 for entropy.
 */
typedef struct _Random Random;


/**
 * @brief Initialises the random state
 */
HXAPI void hx_rand_init(Random *state);


/**
 * @brief Generates random data into the output buffer
 * @param state The random state to process
 * @param data Buffer to fill with random data
 * @param len Length of the buffer (must be 32-bit aligned)
 */
HXAPI void hx_gen_rand(Random *state, void *data, size_t len);


/**
 * @brief Legacy random number generator
 */
HXAPI uint32_t hx_rand(Random *state);


/**
 * @brief A hybrid cryptographic hash function combining MD5 with FNV-1a checksum augmentation
 */
HXAPI size_t hx_aug_md5(const void *data, size_t len, void *digest);


/**
 * @brief Hashes and returns a checksum using the FNV-1a algorithm on the given data
 */
HXAPI uint32_t hx_checksum(const void *data, size_t len, uint32_t seed);


/**
 * @brief This is a multi-purpose LCG XOR encryption algorithm used in the KDX protocol.
 */
HXAPI int hx_crypt(void *data, size_t len, uint32_t seed, uint32_t mul, uint32_t add);


/**
 * @brief This is used for KDX file transfers.
 */
HXAPI int hx_file_crypt(void *data, size_t len, int decrypting);


/**
 * @brief Legacy random number generator given a range
 */
HXAPI uint32_t hx_rand_range(uint32_t *seed, uint32_t minval, uint32_t maxval);


/**
 * @brief Encrypts or decrypts a network packet for TCP
 */
HXAPI int hx_tcp_crypt(uint32_t seed, void *data, size_t len);


/**
 * @brief Used for encryption of UDP packets (server<->tracker)
 */
static inline int hx_udp_crypt(void *data, size_t len)
{
	return hx_crypt(data, len, 0xA5A16C4A, 0x41D28485, 12843);
}

#ifdef __cplusplus
}
#endif // __cplusplus

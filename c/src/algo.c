#include "../include/haxial/algo.h"
#include "../include/haxial/md5.h"

#include <string.h>
#include <time.h>

#define LCG_ADD 12345
#define LCG_MUL 0x41C64E6D

#define MIN(a,b) ((a) < (b) ? (a) : (b))
#define MAX(a,b) ((a) > (b) ? (a) : (b))

struct _Random
{
	uint8_t idx;
	uint32_t seed;
	uint32_t buf[64];
};


void hx_rand_init(Random *state)
{
	if (!state) return;

	memset(state, 0, sizeof(Random));
	state->seed = (uint32_t)time(NULL) & 0xFFFFFFFF;
}


void hx_gen_rand(Random *state, void *data, size_t len)
{
	if (!len)
		return;
	
	while (len > 0)
	{
		MD5_CTX ctx;
		uint8_t digest[16];

		MD5Init(&ctx);
		MD5Update(&ctx, (uint8_t *)&state->buf[0], len);
		MD5Final(&digest, &ctx);

		uint32_t xor = 0xFFFFFFFF;
		size_t toCopy = MIN(len, 8);
		uint8_t *bp = (uint8_t *)data;

		for (size_t i = 0; i < len; i += 8)
			xor ^= *bp++;
	}
}


uint32_t hx_rand(Random *state)
{
	uint32_t sum = hx_checksum(state->buf, 256, state->seed);
	
	state->seed = state->seed * LCG_MUL + LCG_ADD;
	sum ^= state->seed;
	state->buf[state->idx] ^= sum;
	state->idx = sum & 63;

	return sum;
}


uint32_t hx_checksum(const void *data, size_t len, uint32_t seed)
{
	#define PRIME 0x1000193

	const uint8_t *bp = (const uint8_t *)data;

	while (len && ((uintptr_t)data & 3))
	{
		seed = seed * PRIME ^ *bp++; 
		len--;
	}

	const uint32_t *dp = (const uint32_t *)data;
	for (; len >= 4; len -= 4)
		seed = seed * PRIME ^ HTONL(*dp++);
	
	bp = (const uint8_t *)dp;
	while (len--)
		seed = seed * PRIME ^ *bp++;
	
	return seed;
}

#include "x25x.h"
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
//sha3 dir includes for X11
#include "sha3/sph_blake.h"
#include "sha3/sph_bmw.h"
#include "sha3/sph_groestl.h"
#include "sha3/sph_jh.h"
#include "sha3/sph_keccak.h"
#include "sha3/sph_skein.h"
#include "sha3/sph_luffa.h"
#include "sha3/sph_cubehash.h"
#include "sha3/sph_shavite.h"
#include "sha3/sph_simd.h"
#include "sha3/sph_echo.h"
//sha3 dir includes for x25x
#include "sha3/sph_hamsi.h"
#include "sha3/sph_fugue.h"
#include "sha3/sph_shabal.h"
#include "sha3/sph_whirlpool.h"
#include "sha3/sph_sha2.h"
#include "SWIFFTX/SWIFFTX.h"
#include "sha3/sph_tiger.h"
#include "sha3/sph_haval.h"
#include "sha3/sph_panama.h"
#include "sha3/gost_sib.h"
#include "crypto/lyra2.h"
#include "lane/lane.h"
#include "sha3/blake2s.h"

struct simpleBlob
{
    uint8_t specialint[64];
};

/* x25x-hash */
void x25x_hash(const char* input, char* output, uint32_t len)
{
    sph_blake512_context      ctx_blake;
    sph_bmw512_context        ctx_bmw;
    sph_groestl512_context    ctx_groestl;
    sph_jh512_context         ctx_jh;
    sph_keccak512_context     ctx_keccak;
    sph_skein512_context      ctx_skein;
    sph_luffa512_context      ctx_luffa;
    sph_cubehash512_context   ctx_cubehash;
    sph_shavite512_context    ctx_shavite;
    sph_simd512_context       ctx_simd;
    sph_echo512_context       ctx_echo;
    sph_hamsi512_context      ctx_hamsi;
    sph_fugue512_context      ctx_fugue;
    sph_shabal512_context     ctx_shabal;
    sph_whirlpool_context     ctx_whirlpool;
    sph_sha512_context        ctx_sha2;
    sph_haval256_5_context    ctx_haval;
    sph_tiger_context         ctx_tiger;
    sph_gost512_context       ctx_gost;
    sph_sha256_context        ctx_sha;
    sph_panama_context        ctx_panama;

    //these uint512 in the c++ source of the client are backed by an array of uint8_t, this struct is meant to emulate basic blob class usage in modern Bitcoin codebases
    struct simpleBlob hashArr[25] = { 0 };

    sph_blake512_init(&ctx_blake);
    sph_blake512 (&ctx_blake, input, len);
    sph_blake512_close (&ctx_blake, hashArr[0].specialint);

    sph_bmw512_init(&ctx_bmw);
    sph_bmw512 (&ctx_bmw, hashArr[0].specialint, 64);
    sph_bmw512_close(&ctx_bmw, hashArr[1].specialint);

    sph_groestl512_init(&ctx_groestl);
    sph_groestl512 (&ctx_groestl, hashArr[1].specialint, 64);
    sph_groestl512_close(&ctx_groestl, hashArr[2].specialint);

    sph_skein512_init(&ctx_skein);
    sph_skein512 (&ctx_skein, hashArr[2].specialint, 64);
    sph_skein512_close (&ctx_skein, hashArr[3].specialint);

    sph_jh512_init(&ctx_jh);
    sph_jh512 (&ctx_jh, hashArr[3].specialint, 64);
    sph_jh512_close(&ctx_jh, hashArr[4].specialint);

    sph_keccak512_init(&ctx_keccak);
    sph_keccak512 (&ctx_keccak, hashArr[4].specialint, 64);
    sph_keccak512_close(&ctx_keccak, hashArr[5].specialint);
    
    sph_luffa512_init (&ctx_luffa);
    sph_luffa512 (&ctx_luffa, hashArr[5].specialint, 64);
    sph_luffa512_close (&ctx_luffa, hashArr[6].specialint);	
    
    sph_cubehash512_init (&ctx_cubehash); 
    sph_cubehash512 (&ctx_cubehash, hashArr[6].specialint, 64);   
    sph_cubehash512_close(&ctx_cubehash, hashArr[7].specialint);  
    
    sph_shavite512_init (&ctx_shavite);
    sph_shavite512 (&ctx_shavite, hashArr[7].specialint, 64);   
    sph_shavite512_close(&ctx_shavite, hashArr[8].specialint);  
    
    sph_simd512_init (&ctx_simd); 
    sph_simd512 (&ctx_simd, hashArr[8].specialint, 64);   
    sph_simd512_close(&ctx_simd, hashArr[9].specialint); 
    
    sph_echo512_init (&ctx_echo); 
    sph_echo512 (&ctx_echo, hashArr[9].specialint, 64);   
    sph_echo512_close(&ctx_echo, hashArr[10].specialint);

    sph_hamsi512_init(&ctx_hamsi);
    sph_hamsi512 (&ctx_hamsi, hashArr[10].specialint, 64);
    sph_hamsi512_close(&ctx_hamsi, hashArr[11].specialint);

    sph_fugue512_init(&ctx_fugue);
    sph_fugue512 (&ctx_fugue, hashArr[11].specialint, 64);
    sph_fugue512_close(&ctx_fugue, hashArr[12].specialint);

    sph_shabal512_init(&ctx_shabal);
    sph_shabal512 (&ctx_shabal, hashArr[12].specialint, 64);
    sph_shabal512_close(&ctx_shabal, hashArr[13].specialint);

    sph_whirlpool_init(&ctx_whirlpool);
    sph_whirlpool (&ctx_whirlpool, hashArr[13].specialint, 64);
    sph_whirlpool_close(&ctx_whirlpool, hashArr[14].specialint);

    sph_sha512_init(&ctx_sha2);
    sph_sha512 (&ctx_sha2, hashArr[14].specialint, 64);
    sph_sha512_close(&ctx_sha2, hashArr[15].specialint);

    // Temporary var used by swifftx to manage 65 bytes output,
    unsigned char temp[SWIFFTX_OUTPUT_BLOCK_SIZE] = {0};
    InitializeSWIFFTX();
    ComputeSingleSWIFFTX((unsigned char*)hashArr[12].specialint, temp, false);
    memcpy((unsigned char*)hashArr[16].specialint, temp, 64);

    sph_haval256_5_init(&ctx_haval);
    sph_haval256_5 (&ctx_haval, hashArr[16].specialint, 64);
    sph_haval256_5_close(&ctx_haval, hashArr[17].specialint);

    sph_tiger_init(&ctx_tiger);
    sph_tiger (&ctx_tiger, hashArr[17].specialint, 64);
    sph_tiger_close(&ctx_tiger, hashArr[18].specialint);

    LYRA2(hashArr[19].specialint, 32, hashArr[18].specialint, 32, hashArr[18].specialint, 32, 1, 4, 4);

    sph_gost512_init(&ctx_gost);
    sph_gost512 (&ctx_gost, hashArr[19].specialint, 64);
    sph_gost512_close(&ctx_gost, hashArr[20].specialint);

    sph_sha256_init(&ctx_sha);
    sph_sha256 (&ctx_sha, hashArr[20].specialint, 64);
    sph_sha256_close(&ctx_sha, hashArr[21].specialint);

    sph_panama_init(&ctx_panama);
    sph_panama (&ctx_panama, hashArr[21].specialint, 64);
    sph_panama_close(&ctx_panama, hashArr[22].specialint);

    laneHash(512, (BitSequence*)hashArr[22].specialint, 512, (BitSequence*)hashArr[23].specialint);

	// simple shuffle algorithm
	#define X25X_SHUFFLE_BLOCKS (24 /* number of algos so far */ * 64 /* output bytes per algo */ / 2 /* block size */)

    #define X25X_SHUFFLE_ROUNDS 12
	static const uint16_t x25x_round_const[X25X_SHUFFLE_ROUNDS] = {
		0x142c, 0x5830, 0x678c, 0xe08c,
		0x3c67, 0xd50d, 0xb1d8, 0xecb2,
		0xd7ee, 0x6783, 0xfa6c, 0x4b9c
	};

	uint16_t* block_pointer = (uint16_t*)hashArr;
	for (int r = 0; r < X25X_SHUFFLE_ROUNDS; r++) {
		for (int i = 0; i < X25X_SHUFFLE_BLOCKS; i++) {
			uint16_t block_value = block_pointer[X25X_SHUFFLE_BLOCKS - i - 1];
			block_pointer[i] ^= block_pointer[block_value % X25X_SHUFFLE_BLOCKS] + (x25x_round_const[r] << (i % 16));
		}
	}
    blake2s_simple((uint8_t*)hashArr[24].specialint, hashArr[0].specialint, 64 * 24);

    memcpy(output, hashArr[24].specialint, 32);
}

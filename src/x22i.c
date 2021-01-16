#include "x22i.h"
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
//sha3 dir includes for x22i
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

/* x22i-hash */
void x22i_hash(const char* input, char* output, uint32_t len)
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

    //these uint512 in the c++ source of the client are backed by an array of uint32
    uint32_t hashA[16], hashB[16];	

    sph_blake512_init(&ctx_blake);
    sph_blake512 (&ctx_blake, input, len);
    sph_blake512_close (&ctx_blake, hashA);

    sph_bmw512_init(&ctx_bmw);
    sph_bmw512 (&ctx_bmw, hashA, 64);
    sph_bmw512_close(&ctx_bmw, hashB);

    sph_groestl512_init(&ctx_groestl);
    sph_groestl512 (&ctx_groestl, hashB, 64);
    sph_groestl512_close(&ctx_groestl, hashA);

    sph_skein512_init(&ctx_skein);
    sph_skein512 (&ctx_skein, hashA, 64);
    sph_skein512_close (&ctx_skein, hashB);

    sph_jh512_init(&ctx_jh);
    sph_jh512 (&ctx_jh, hashB, 64);
    sph_jh512_close(&ctx_jh, hashA);

    sph_keccak512_init(&ctx_keccak);
    sph_keccak512 (&ctx_keccak, hashA, 64);
    sph_keccak512_close(&ctx_keccak, hashB);
    
    sph_luffa512_init (&ctx_luffa);
    sph_luffa512 (&ctx_luffa, hashB, 64);
    sph_luffa512_close (&ctx_luffa, hashA);	
    
    sph_cubehash512_init (&ctx_cubehash); 
    sph_cubehash512 (&ctx_cubehash, hashA, 64);   
    sph_cubehash512_close(&ctx_cubehash, hashB);  
    
    sph_shavite512_init (&ctx_shavite);
    sph_shavite512 (&ctx_shavite, hashB, 64);   
    sph_shavite512_close(&ctx_shavite, hashA);  
    
    sph_simd512_init (&ctx_simd); 
    sph_simd512 (&ctx_simd, hashA, 64);   
    sph_simd512_close(&ctx_simd, hashB); 
    
    sph_echo512_init (&ctx_echo); 
    sph_echo512 (&ctx_echo, hashB, 64);   
    sph_echo512_close(&ctx_echo, hashA);

    sph_hamsi512_init(&ctx_hamsi);
    sph_hamsi512 (&ctx_hamsi, hashA, 64);
    sph_hamsi512_close(&ctx_hamsi, hashB);

    sph_fugue512_init(&ctx_fugue);
    sph_fugue512 (&ctx_fugue, hashB, 64);
    sph_fugue512_close(&ctx_fugue, hashA);

    sph_shabal512_init(&ctx_shabal);
    sph_shabal512 (&ctx_shabal, hashA, 64);
    sph_shabal512_close(&ctx_shabal, hashB);

    sph_whirlpool_init(&ctx_whirlpool);
    sph_whirlpool (&ctx_whirlpool, hashB, 64);
    sph_whirlpool_close(&ctx_whirlpool, hashA);

    sph_sha512_init(&ctx_sha2);
    sph_sha512 (&ctx_sha2, hashA, 64);
    sph_sha512_close(&ctx_sha2, hashB);

    // Temporary var used by swifftx to manage 65 bytes output,
    unsigned char temp[SWIFFTX_OUTPUT_BLOCK_SIZE] = {0};
    InitializeSWIFFTX();
    ComputeSingleSWIFFTX((unsigned char*)hashA, temp, false);
    memcpy((unsigned char*)hashA, temp, 64);

    sph_haval256_5_init(&ctx_haval);
    sph_haval256_5 (&ctx_haval, hashA, 64);
    sph_haval256_5_close(&ctx_haval, hashB);

    sph_tiger_init(&ctx_tiger);
    sph_tiger (&ctx_tiger, hashB, 64);
    sph_tiger_close(&ctx_tiger, hashA);

    LYRA2(hashB, 32, hashA, 32, hashA, 32, 1, 4, 4);

    sph_gost512_init(&ctx_gost);
    sph_gost512 (&ctx_gost, hashB, 64);
    sph_gost512_close(&ctx_gost, hashA);

    sph_sha256_init(&ctx_sha);
    sph_sha256 (&ctx_sha, hashB, 64);
    sph_sha256_close(&ctx_sha, hashA);

    memcpy(output, hashA, 32);
}

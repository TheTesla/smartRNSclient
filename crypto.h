#ifndef CRYPTO_H_INCLUDED
#define CRYPTO_H_INCLUDED

#include <vector>
#include <string>
#include <crypto++/modes.h>
#include <crypto++/aes.h>
#include <crypto++/filters.h>
#include <crypto++/md5.h>
#include <crypto++/sha.h>
#include <crypto++/hex.h>
#include <crypto++/base64.h>
#include <iostream>


#define CIPHERLEN 128

using namespace std;
using namespace CryptoPP;

string hashdomain(string request);
void base64dec(byte* dec, byte* base64arr, uint32_t len = CIPHERLEN*8/6+1);
void base64dec(byte* dec, string base64str);
void AESdec(byte* decpt, u_char* cipher, string keystr);
string AESdec(u_char* cipher, string keystr);




#endif // CRYPTO_H_INCLUDED

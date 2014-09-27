
#include "crypto.h"




string hashdomain(string request)
{
    CryptoPP::SHA hash;
    CryptoPP::HexEncoder encoder;
    std::string output, domain;

    byte digest[CryptoPP::SHA::DIGESTSIZE];
    hash.CalculateDigest(digest, (byte*) domain.c_str(), domain.length());

    encoder.Attach(new CryptoPP::StringSink(output));
    encoder.Put(digest, sizeof(digest));
    encoder.MessageEnd();

    return output;
}

void base64dec(byte* dec, byte* base64arr, uint32_t len)
{
    Base64Decoder b64d;
    b64d.Attach(new ArraySink((byte*)dec, CIPHERLEN));
    b64d.Put(base64arr, len);
    b64d.MessageEnd();
}

void base64dec(byte* dec, string base64str)
{
    base64dec(dec, (byte*) base64str.c_str(), base64str.size());
}

void AESdec(byte* decpt, u_char* cipher, string keystr)
{
    byte iv[AES::BLOCKSIZE];
    byte key[AES::MAX_KEYLENGTH];
    uint32_t i;
    for(i=0;i<AES::BLOCKSIZE;i++){
        iv[i] = 0;
    }
    for(i=0;i<AES::MAX_KEYLENGTH;i++){
        if(i<keystr.length()){
            key[i] = keystr[i];
        }else{
            key[i] = 0;
        }
    }

    strcpy((char*)key, keystr.c_str());
    CBC_Mode<AES>::Decryption aesdec(key, AES::MAX_KEYLENGTH, iv);
    aesdec.ProcessData(decpt, cipher, CIPHERLEN);
}

string AESdec(u_char* cipher, string keystr)
{
    byte decb[CIPHERLEN];
    AESdec(decb, cipher, keystr);
    string decstr(reinterpret_cast<const char*>(decb));
    return decstr;
}

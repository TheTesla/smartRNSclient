
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


void base32dec(byte* dec, byte* base32arr, uint32_t len)
{
    Base32Decoder b32d;
    b32d.Attach(new ArraySink((byte*)dec, CIPHERLEN));
    b32d.Put(base32arr, len);
    b32d.MessageEnd();
}

void base16dec(byte* dec, byte* base16arr, uint32_t len)
{
    HexDecoder b16d;
    b16d.Attach(new ArraySink((byte*)dec, CIPHERLEN));
    b16d.Put(base16arr, len);
    b16d.MessageEnd();
}

void nodec(byte* dec, byte* nocod, uint32_t len)
{
    strncpy((char*) dec, (char*) nocod, len);
}

void base64dec(byte* dec, string base64str)
{
    base64dec(dec, (byte*) base64str.c_str(), base64str.size());
}

void base32dec(byte* dec, string base32str)
{
    base32dec(dec, (byte*) base32str.c_str(), base32str.size());
}

void base16dec(byte* dec, string base16str)
{
    base16dec(dec, (byte*) base16str.c_str(), base16str.size());
}

void nodec(byte* dec, string nocodstr)
{
    nodec((byte*) dec, (byte*) nocodstr.c_str(), nocodstr.size());
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

void nocrypt(byte* decpt, u_char* nocipher)
{
    strncpy((char*) decpt, (char*) nocipher, CIPHERLEN);
}

string nocrypt(u_char* nocipher)
{
    string decstr(reinterpret_cast<const char*>(nocipher));
    return decstr;
}

string b64AESdec(string b64cipher, string keystr)
{
    byte b64decarr[CIPHERLEN*8/6+1];
    base64dec(b64decarr, b64cipher);
    return AESdec(b64decarr, keystr);
}

string b32AESdec(string b32cipher, string keystr)
{
    byte b32decarr[CIPHERLEN*8/5+1];
    base32dec(b32decarr, b32cipher);
    return AESdec(b32decarr, keystr);
}

string b16AESdec(string b16cipher, string keystr)
{
    byte b16decarr[CIPHERLEN*8/4+1];
    base16dec(b16decarr, b16cipher);
    return AESdec(b16decarr, keystr);
}

vector<string> b64AESdec(vector<string> b64cipher, string keystr)
{
    uint32_t i;
    vector<string> decvec;
    string decstr;
    for(i=0;i<b64cipher.size();i++){
        decvec.push_back(b64AESdec(b64cipher[i], keystr));
    }
    return decvec;
}

vector<string> b32AESdec(vector<string> b32cipher, string keystr)
{
    uint32_t i;
    vector<string> decvec;
    string decstr;
    for(i=0;i<b32cipher.size();i++){
        decvec.push_back(b32AESdec(b32cipher[i], keystr));
    }
    return decvec;
}

vector<string> b16AESdec(vector<string> b16cipher, string keystr)
{
    uint32_t i;
    vector<string> decvec;
    string decstr;
    for(i=0;i<b16cipher.size();i++){
        decvec.push_back(b16AESdec(b16cipher[i], keystr));
    }
    return decvec;
}

vector<string> decrypt (vector<string> cipher, string keystr, primenc_et contprimenc, contenc_et contsecenc)
{
    byte primdecarr[CIPHERLEN*2+1];
    uint32_t i;
    vector<string> decvec;
    for(i=0;i<cipher.size();i++){
        if(NO_PRIMENC == contprimenc){
            nodec(primdecarr, cipher[i]);
        }else if(BASE64 == contprimenc){
            base64dec(primdecarr, cipher[i]);
        }else if(BASE32 == contprimenc){
            base32dec(primdecarr, cipher[i]);
        }else if(BASE16 == contprimenc){
            base16dec(primdecarr, cipher[i]);
        }else{
            throw contprimenc;
            cout << "This primary encoding is not supported yet." << endl;
        }


        if(NO_CONTENC == contsecenc){
            decvec.push_back(nocrypt(primdecarr));
        }else if(AES_128 == contsecenc){
            decvec.push_back(AESdec(primdecarr, keystr));
        }else{
            throw contsecenc;
            cout << "This secondary encoding is not supported yet." << endl;
        }
    }

    return decvec;
}

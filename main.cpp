#include <iostream>

#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include <string>

#include <crypto++/modes.h>
#include <crypto++/aes.h>
#include <crypto++/filters.h>
#include <crypto++/md5.h>
#include <crypto++/sha.h>
#include <crypto++/hex.h>
#include <crypto++/base64.h>




#define N 4096

#define CIPHERLEN 128


using namespace std;
using namespace CryptoPP;



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

void base64dec(byte* dec, byte* base64arr)
{
    Base64Decoder b64d;
    b64d.Attach(new ArraySink((byte*)dec, CIPHERLEN));
    b64d.Put(base64arr, CIPHERLEN*8/6+1);
    b64d.MessageEnd();
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

int main()
{
    u_char nsbuf[N];
    char dispbuf[N];
    ns_msg msg;
    ns_rr rr;
    uint32_t l;
    uint32_t i;
    string domain, domainhash, request, output;
    byte b64decarr[CIPHERLEN*8/6+1];
    byte decptarr[CIPHERLEN];


    request = "stefan.helmert@entroserv.de";



    output = hashdomain(request);


    cout << request << endl;

    domain = output.substr(0,35)+'.'+request.substr(request.find_first_of("@")+1);
    cout << endl << domain << " " << domain.length() << endl;

    res_init();
    l = res_query(domain.c_str(), ns_c_any, ns_t_any, nsbuf, sizeof(nsbuf));
    ns_initparse(nsbuf, l, &msg);
    l = ns_msg_count(msg, ns_s_an);
    for (i = 0; i < l; i++)
    {
        ns_parserr(&msg, ns_s_an, i, &rr);
        u_char const* rdata = ns_rr_rdata(rr);
        base64dec(b64decarr, (byte*)rdata);
        AESdec(decptarr, b64decarr, request);
        cout << endl << decptarr << endl;
        ns_sprintrr(&msg, &rr, NULL, NULL, dispbuf, sizeof(dispbuf));
        cout << endl << dispbuf << endl;
    }


    cout << endl;
    return 0;
}


#include <iostream>

#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include <string>
#include <vector>

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

void base64dec(byte* dec, byte* base64arr, uint32_t len = CIPHERLEN*8/6+1)
{
    Base64Decoder b64d;
    b64d.Attach(new ArraySink((byte*)dec, CIPHERLEN));
    b64d.Put(base64arr, len);
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


int getTXTrecs(string domain, u_char  (*TXTs) [256], uint32_t maxTXTs)
{
    u_char nsbuf[N];
    ns_msg msg;
    ns_rr rr;
    uint32_t l;
    uint32_t i;

    res_init();
    l = res_query(domain.c_str(), ns_c_in, ns_t_txt, nsbuf, sizeof(nsbuf));
    ns_initparse(nsbuf, l, &msg);
    l = ns_msg_count(msg, ns_s_an);

    for (i = 0; (i < l) && (i < maxTXTs); i++)
    {
        ns_parserr(&msg, ns_s_an, i, &rr);
        u_char const* rdata = ns_rr_rdata(rr);
        if(0==rdata) {
            return -2;
        }
        strncpy((char*)TXTs[i], (char*)rdata, rdata[0]+1);
    }
    return l;
}


typedef enum urienc_e
{
    NO_URIENC   =   0,
    SHA_1       =   1,
    SHA_2       = 256,
    SHA_224     = 224,
    SHA_256     = 256,
    SHA_384     = 384,
    SHA_512     = 512,
    SHA_3       =   3
} urienc_et;

typedef enum contenc_e
{
    NO_CONTENC  =   0,
    AES_128     =   128
} contenc_et;


typedef struct smartrns_conf_s
{
    string version;
    urienc_et urienc;
    uint32_t subdomlen;
    contenc_et contenc;
    string salt;
} smartrns_conf_t;

typedef struct keyval_s
{
    string key;
    string val;
} keyval_t;


vector<keyval_t> txtrecstr2smartrnsconfig(string txtstr)
{
    vector<keyval_t> confvec;
    keyval_t confelem;
    uint32_t i, k;
    string key, keysstr, val;
    vector<string> keys;
    size_t pos;

    key = "";
    keys.clear();

    i = 0;
    try{
        while(std::string::npos!=pos){ // iterate over TXTrecord
            pos = txtstr.find_first_not_of(" "); // delete all spaces...
            txtstr = txtstr.substr(pos); // ...from beginning
            if("}"==txtstr.substr(0,1)){ // exit {...} expression
                keys.pop_back();
            }
            pos = txtstr.find_first_of("{=; "); // variable name ended, expression begins
            key = txtstr.substr(0,pos); // get variable name
            if("."==key.substr(0,1)){ // delete beginning "." of name (if structure{ .element1=...)
                key = key.substr(1);
            }
            txtstr = txtstr.substr(pos);
            pos = txtstr.find_first_not_of(" "); // delete trailing spaces
            txtstr = txtstr.substr(pos);

            if("="==txtstr.substr(0,1)){ // assignement
                pos = txtstr.find_first_of(";"); // assigned value ends with ";"
                val = txtstr.substr(1,pos-1);
                keysstr = "";
                for(k=0;k<keys.size();k++){ // get the complete name if structure{.element=...} is used -> structure.element
                    keysstr += keys[k] + ".";
                }
                confelem.key = keysstr + key; // build complete variable name and save to key-value-pair
                confelem.val = val; // ... add the value
                confvec.push_back(confelem);
                i++; // ... next key-val-pair
                txtstr = txtstr.substr(pos+1);
            }else if("{"==txtstr.substr(0,1)){ // shorted structure initialisation starts: structurename{.elem1=42; .elem2=23}
                keys.push_back(key); // do the structurename on top of the stack - yes, nesting is possible
                txtstr = txtstr.substr(pos+1);

            }

        }
    }
    catch( std::exception const &exc){ // config ends
    }

    return confvec;

}


urienc_et uriencstr2enum(string str)
{
    if("SHA-1"      == str) return SHA_1;
    if("SHA-2"      == str) return SHA_2;
    if("SHA-224"    == str) return SHA_224;
    if("SHA-256"    == str) return SHA_256;
    if("SHA-3"      == str) return SHA_3;
    if("SHA-384"    == str) return SHA_384;
    if("SHA-512"    == str) return SHA_512;
    return NO_URIENC;
}

contenc_et contencstr2enum(string str)
{
    if("AES-128"        == str) return AES_128;
    return NO_CONTENC;
}

smartrns_conf_t txtrec2smartrnsconf(u_char* txtrec)
{
    vector<keyval_t> confvec;
    uint32_t i;
    string txt, txtstr;
    smartrns_conf_t smartrnsconf;



    txt.assign((const char*)txtrec);
    txtstr = txt.substr(1); // delete length-entry

    confvec = txtrecstr2smartrnsconfig(txtstr);

    for(i=0;i<confvec.size();i++){
        if("smartrns.version" == confvec[i].key){
            smartrnsconf.version = confvec[i].val;
        }else if("smartrns.salt" == confvec[i].key){
            smartrnsconf.salt = confvec[i].val;
        }else if("smartrns.urienc" == confvec[i].key){
            smartrnsconf.urienc = uriencstr2enum(confvec[i].val);
        }else if("smartrns.subdomlen" == confvec[i].key){
            smartrnsconf.subdomlen = atoi(confvec[i].val.c_str());
        }else if("smartrns.contenc" == confvec[i].key){
            smartrnsconf.contenc = contencstr2enum(confvec[i].val);
        }

        cout << confvec[i].key << " " << confvec[i].val << endl;
    }

    cout << smartrnsconf.version << " " << smartrnsconf.salt << " " << smartrnsconf.urienc << " " << smartrnsconf.subdomlen << " " << smartrnsconf.contenc << endl;

    return smartrnsconf;
}

int main(int argc, char *argv[])
{
    u_char nsbuf[N];
    char dispbuf[N];
    ns_msg msg;
    ns_rr rr;
    uint32_t l;
    uint32_t i;
    string domain, domainhash, request, output, topdomain;
    byte b64decarr[CIPHERLEN*8/6+1];
    byte decptarr[CIPHERLEN];


    u_char txts[256][256];

    if(2!=argc){
        cout << "Please specify Domain to lookup!" << endl;
        return 0;
    }

    //request = "stefan.helmert@entroserv.de";
    request = argv[1];

    // everything after the @
    topdomain = request.substr(request.find_first_of("@")+1);

    cout << getTXTrecs(topdomain, txts, 4);
    cout << txts[0] << endl << txts[1]  << endl;

    txtrec2smartrnsconf(txts[0]);


    return 0;

    output = hashdomain(request);


    cout << request << endl;

    domain = output.substr(0,35)+'.'+request.substr(request.find_first_of("@")+1);
    cout << endl << domain << " " << domain.length() << endl;

    res_init();
    l = res_query(domain.c_str(), ns_c_any, ns_t_any, nsbuf, sizeof(nsbuf));
    ns_initparse(nsbuf, l, &msg);
    l = ns_msg_count(msg, ns_s_an);
    cout << l << endl;
    for (i = 0; i < l; i++)
    {
        ns_parserr(&msg, ns_s_an, i, &rr);
        u_char const* rdata = ns_rr_rdata(rr);
        if(0==rdata) {
            cout << "Kein Eintrag!" << endl;
            return 0;
        }
        cout << (unsigned)rdata[0] << endl;
        if(0==rdata[0]){
            cout << "Leerer Eintrag!" << endl;
            return 0;
        }
        base64dec(b64decarr, (byte*)rdata, rdata[0]);
        AESdec(decptarr, b64decarr, request);
        cout << endl << decptarr << endl;
        ns_sprintrr(&msg, &rr, NULL, NULL, dispbuf, sizeof(dispbuf));
        cout << endl << dispbuf << endl;
    }


    cout << endl;
    return 0;
}


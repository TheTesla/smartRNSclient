#ifndef CONFIGURATION_H_INCLUDED
#define CONFIGURATION_H_INCLUDED

#include <vector>
#include <string>
#include "parse.h"

using namespace std;

typedef enum urienc_e
{
    URIENC_NOT_SPEC = -1,
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
    CONTENC_NOT_SPEC = -1,
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
    bool passwd;
    bool subdom;
} smartrns_conf_t;







vector<keyval_t> txtrecstrparse(string txtstr);
smartrns_conf_t confvec2smartrnsconf(vector<keyval_t> confvec);
smartrns_conf_t txtrec2smartrnsconf(u_char* txtrec);


#endif // CONFIGURATION_H_INCLUDED

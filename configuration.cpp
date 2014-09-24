

#include "configuration.h"


#include <iostream>


urienc_et uriencstr2enum(string str)
{
    if("NONE"       == str) return NO_URIENC;
    if("SHA-1"      == str) return SHA_1;
    if("SHA-2"      == str) return SHA_2;
    if("SHA-224"    == str) return SHA_224;
    if("SHA-256"    == str) return SHA_256;
    if("SHA-3"      == str) return SHA_3;
    if("SHA-384"    == str) return SHA_384;
    if("SHA-512"    == str) return SHA_512;
    return URIENC_NOT_SPEC;
}

contenc_et contencstr2enum(string str)
{
    if("NONE"           == str) return NO_CONTENC;
    if("AES-128"        == str) return AES_128;
    return CONTENC_NOT_SPEC;
}




smartrns_conf_t smartrnsvec2smartrnsconf(vector<keyval_t> smartrnsvec)
{
    uint32_t i;
    string txt, txtstr;
    smartrns_conf_t smartrnsconf;

    smartrnsconf.version   = "";
    smartrnsconf.subdom    = false;
    smartrnsconf.passwd    = false;
    smartrnsconf.salt      = "";
    smartrnsconf.urienc    = URIENC_NOT_SPEC;
    smartrnsconf.subdomlen = 0;
    smartrnsconf.contenc   = CONTENC_NOT_SPEC;

    for(i=0;i<smartrnsvec.size();i++){
        if("smartrns.conf.version" == smartrnsvec[i].key){
            smartrnsconf.version = smartrnsvec[i].val;
        }else if("smartrns.conf.salt" == smartrnsvec[i].key){
            smartrnsconf.salt = smartrnsvec[i].val;
        }else if("smartrns.conf.urienc" == smartrnsvec[i].key){
            smartrnsconf.urienc = uriencstr2enum(smartrnsvec[i].val);
        }else if("smartrns.conf.subdomlen" == smartrnsvec[i].key){
            smartrnsconf.subdomlen = atoi(smartrnsvec[i].val.c_str());
        }else if("smartrns.conf.passwd" == smartrnsvec[i].key){
            smartrnsconf.passwd = true;
        }else if("smartrns.conf.subdom" == smartrnsvec[i].key){
            smartrnsconf.subdom = true;
        }else if("smartrns.conf.contenc" == smartrnsvec[i].key){
            smartrnsconf.contenc = contencstr2enum(smartrnsvec[i].val);
        }

        cout << smartrnsvec[i].key << " " << smartrnsvec[i].val << endl;
    }

    cout << smartrnsconf.version << " " << smartrnsconf.salt << " " << smartrnsconf.urienc << " " << smartrnsconf.subdomlen << " " << smartrnsconf.contenc << " " << smartrnsconf.passwd << " " << smartrnsconf.subdom << endl;

    return smartrnsconf;
}




smartrns_conf_t txtrec2smartrnsconf(u_char* txtrec)
{
    vector<keyval_t> smartrnsvec;
    string txt, txtstr;

    txt.assign((const char*)txtrec);
    txtstr = txt.substr(1); // delete length-entry

    smartrnsvec = txtrecstrparse(txtstr);

    return smartrnsvec2smartrnsconf(smartrnsvec);
}


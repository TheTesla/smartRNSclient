

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
                txtstr = txtstr.substr(1);
                pos = txtstr.find_first_not_of(" "); // delete trailing spaces
                txtstr = txtstr.substr(pos);
                pos = txtstr.find_first_of(";"); // assigned value ends with ";"
                val = txtstr.substr(0,pos);
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


smartrns_conf_t txtrec2smartrnsconf(u_char* txtrec)
{
    vector<keyval_t> confvec;
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
        }else if("smartrns.passwd" == confvec[i].key){
            smartrnsconf.passwd = true;
        }else if("smartrns.subdom" == confvec[i].key){
            smartrnsconf.subdom = true;
        }else if("smartrns.contenc" == confvec[i].key){
            smartrnsconf.contenc = contencstr2enum(confvec[i].val);
        }

        cout << confvec[i].key << " " << confvec[i].val << endl;
    }

    cout << smartrnsconf.version << " " << smartrnsconf.salt << " " << smartrnsconf.urienc << " " << smartrnsconf.subdomlen << " " << smartrnsconf.contenc << " " << smartrnsconf.passwd << " " << smartrnsconf.subdom << endl;

    return smartrnsconf;
}


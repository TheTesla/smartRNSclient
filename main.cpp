
/*  Copyright (C) 2014 Stefan Helmert <stefan.helmert@gmx.net>
    smartRNS-Query-Client
*/


#include <iostream>

#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include <string>
#include <vector>
#include "configuration.h"
#include "data.h"
#include "parse.h"
#include "crypto.h"
#include "dnsquery.h"


using namespace std;

// get the right side of "@"
string uritop(string uri, size_t* pos)
{
    uri = '@' + uri;
    *pos = uri.find_last_of('@');
    return uri.substr(*pos+1);
}

// get the next subdomain-part, e. h. public.myname@smartrns.net -> get "myname" and then get "public"
string uripart(string uri, size_t* pos)
{
    size_t newpos;
    string partstr;
    uri = '.'+uri;
    newpos = uri.find_last_of('.', *pos-1);
    partstr = uri.substr(newpos+1, newpos - *pos);
    *pos = newpos;
    return partstr;
}

// tell the next domain to reuqest - in encrypted/converted form
string getdomain(string uri, size_t* pos, uint32_t subdomlen, primenc_et primenc, urienc_et urienc, string salt)
{
    string suburi;
    byte encdom[CryptoPP::SHA::DIGESTSIZE];
    suburi = uripart(uri, pos);

    if(NO_PRIMENC == primenc){
        if(NO_URIENC == urienc){
            return suburi;
        }
        nourienc(encdom, salt+uri.substr(*pos));
    }

    if(NO_URIENC == urienc){
        nourienc(encdom, salt+uri.substr(*pos));
    }else if(SHA_1 == urienc){
        sha1(encdom, salt+uri.substr(*pos));
    }else if(SHA_224 == urienc){
        sha224(encdom, salt+uri.substr(*pos));
    }else if(SHA_256 == urienc){
        sha256(encdom, salt+uri.substr(*pos));
    }else if(SHA_384 == urienc){
        sha384(encdom, salt+uri.substr(*pos));
    }else if(SHA_512 == urienc){
        sha512(encdom, salt+uri.substr(*pos));
    }else{
        cout << "getdomain() - secondary encoding not supported!" << endl;
        throw urienc;
        return "";
    }

    if(BASE16 == primenc){
        return base16enc(encdom, CryptoPP::SHA::DIGESTSIZE).substr(0,subdomlen);
    }else if(BASE32 == primenc){
        return base32enc(encdom, CryptoPP::SHA::DIGESTSIZE).substr(0,subdomlen);
    }else if(NO_PRIMENC == primenc){
        cout << "getdomain() - combination not supported! Hashed value must be primencoded!" << endl;
        throw primenc;
        return "";
    }else{
        cout << "getdomain() - primary encoding not supported!" << endl;
        throw primenc;
        return "";
    }

    return "";
}


int main(int argc, char *argv[])
{
    string domain, request;
    vector<string> decvec;
    smartrns_conf_t conf;
    smartrns_data_t data;
    vector<keyval_t> keyvalvec;
    size_t pos = 0;


    conf.contenc = NO_CONTENC;
    conf.contprimenc = NO_PRIMENC;

    vector<string> txts;

    if(2!=argc){
        cout << endl;
        cout << "Please specify Domain to lookup!" << endl;
        cout << endl;
        cout << "    Copyright (C) 2014 Stefan Helmert <stefan.helmert@gmx.net>" << endl;
        cout << endl;
        cout << "    This Program is designed to query and decode smartRNS data over standard DNS." << endl;
        cout << "USAGE: smartRNSclient YourName@smartrns.net" << endl;
        return 0;
    }

    // the domain to query
    request = argv[1];

    // everything after the @
    domain = uritop(request, &pos);

    // now before the @
    while(1){ // recursion over all subdomains
        cout << "REQUEST" << endl << endl << "    " << domain << endl << endl;

        // get the DNS records
        txts = getTXTrecs(domain, 4);

        // do decryption of requestet DNS content
        decvec = decrypt(txts, conf.salt+request, conf.contprimenc, conf.contenc);
        // interprete the content
        keyvalvec = txtrec2keyvalvec(decvec);
        print_key_val_vec(keyvalvec);   // output
        conf = smartrnsvec2smartrnsconf(keyvalvec);
        print_smartrns_config(conf);    // output
        data = smartrnsvec2smartrnsdata(keyvalvec);
        print_smartrns_data(data);      // output

        if(0==pos) break; // no remaining subdomain
        // next subdomain
        try{
            domain = getdomain(request, &pos, conf.subdomlen, conf.uriprimenc, conf.urienc, conf.salt)+'.'+domain;
        }
        catch(const urienc_et& e){
            if(URIENC_NOT_SPEC){
                cout << "URI encoding of subdomain not specified in configuration, aborting!" << endl;
            }
            break;
        }
    }

    return 0;
}


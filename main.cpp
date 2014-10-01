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

string uritop(string uri, size_t* pos)
{
    uri = '@' + uri;
    *pos = uri.find_last_of('@');
    return uri.substr(*pos+1);
}

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


string getdomain(string uri, size_t* pos, uint32_t subdomlen, primenc_et primenc, urienc_et urienc)
{
    string suburi;
    suburi = uripart(uri, pos);
    if(NO_PRIMENC == primenc){
        if(NO_URIENC == urienc){
            return suburi;
        }
    }else if(BASE16 == primenc){
        if(SHA_1 == urienc){
            return hashdomain(uri.substr(*pos)).substr(0,subdomlen);
        }
    }
    cout << "get domain - encoding not supported!" << endl;
    return "";
}

int main(int argc, char *argv[])
{
    string domain, domainhash, request, output, topdomain;
    string decstr;
    vector<string> decvec;
    smartrns_conf_t conf;
    smartrns_data_t data;
    vector<keyval_t> keyvalvec;
    size_t pos = 0;


    conf.contenc = NO_CONTENC;
    conf.contprimenc = NO_PRIMENC;

    vector<string> txts;

    if(2!=argc){
        cout << "Please specify Domain to lookup!" << endl;
        return 0;
    }

    //request = "stefan.helmert@entroserv.de";
    request = argv[1];

    // everything after the @
    domain = uritop(request, &pos);

    // now before the @
    while(0 != pos){
        txts = getTXTrecs(domain, 4);

        cout << txts[0] << endl;

        decvec = decrypt(txts, request, conf.contprimenc, conf.contenc);
        keyvalvec = txtrec2keyvalvec(decvec);
        print_key_val_vec(keyvalvec);
        conf = smartrnsvec2smartrnsconf(keyvalvec);
        print_smartrns_config(conf);
        data = smartrnsvec2smartrnsdata(keyvalvec);
        print_smartrns_data(data);

        domain = getdomain(request, &pos, conf.subdomlen, conf.uriprimenc, conf.urienc)+'.'+domain;
        cout << domain  << " " << pos << endl;
    }


    cout << decstr << endl;

    return 0;
}


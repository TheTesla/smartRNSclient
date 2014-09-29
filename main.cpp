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



int main(int argc, char *argv[])
{
    string domain, domainhash, request, output, topdomain;
    string decstr;
    vector<string> decvec;
    smartrns_conf_t conf;
    smartrns_data_t data;
    vector<keyval_t> keyvalvec;



    vector<string> txts;

    if(2!=argc){
        cout << "Please specify Domain to lookup!" << endl;
        return 0;
    }

    //request = "stefan.helmert@entroserv.de";
    request = argv[1];

    // everything after the @
    topdomain = request.substr(request.find_first_of("@")+1);

    txts = getTXTrecs(topdomain, 4);

    cout << txts[0] << endl;

    keyvalvec = txtrec2keyvalvec(txts);
    print_key_val_vec(keyvalvec);
    conf = smartrnsvec2smartrnsconf(keyvalvec);
    print_smartrns_config(conf);
    data = smartrnsvec2smartrnsdata(keyvalvec);
    print_smartrns_data(data);


    // now before the @
    output = hashdomain(request);
    domain = output.substr(0,conf.subdomlen)+'.'+request.substr(request.find_first_of("@")+1);

    txts = getTXTrecs(domain, 4);
    //cout << txts[0] << endl;

    decvec = decrypt(txts, request, conf.contprimenc, conf.contenc);
    keyvalvec = txtrec2keyvalvec(decvec);
    print_key_val_vec(keyvalvec);
    conf = smartrnsvec2smartrnsconf(keyvalvec);
    print_smartrns_config(conf);
    data = smartrnsvec2smartrnsdata(keyvalvec);
    print_smartrns_data(data);
    cout << decstr << endl;

    return 0;
}


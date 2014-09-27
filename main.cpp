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
    u_char nsbuf[N];
    char dispbuf[N];
    ns_msg msg;
    ns_rr rr;
    uint32_t l;
    uint32_t i;
    string domain, domainhash, request, output, topdomain;
    string decstr;
    smartrns_conf_t conf;
    smartrns_data_t data;
    vector<keyval_t> keyvalvec;

    byte b64decarr[CIPHERLEN*8/6+1];
    byte decptarr[CIPHERLEN];


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
    base64dec(b64decarr, txts[0]);
    decstr = AESdec(b64decarr, request);
    keyvalvec = txtrecstrparse(decstr);
    print_key_val_vec(keyvalvec);
    conf = smartrnsvec2smartrnsconf(keyvalvec);
    print_smartrns_config(conf);
    data = smartrnsvec2smartrnsdata(keyvalvec);
    print_smartrns_data(data);
    cout << decstr << endl;

    return 0;



    cout << request << endl;

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

        cout << endl << decptarr << endl;
        ns_sprintrr(&msg, &rr, NULL, NULL, dispbuf, sizeof(dispbuf));
        cout << endl << dispbuf << endl;
    }


    cout << endl;
    return 0;
}


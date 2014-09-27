
#include "dnsquery.h"



vector<string> getTXTrecs(string domain, uint32_t maxTXTs)
{
    u_char nsbuf[N];
    ns_msg msg;
    ns_rr rr;
    uint32_t l;
    uint32_t i;
    string TXT;
    vector<string> TXTs;

    res_init();
    l = res_query(domain.c_str(), ns_c_in, ns_t_txt, nsbuf, sizeof(nsbuf));
    ns_initparse(nsbuf, l, &msg);
    l = ns_msg_count(msg, ns_s_an);

    for (i = 0; (i < l) && (i < maxTXTs); i++)
    {
        ns_parserr(&msg, ns_s_an, i, &rr);
        u_char const* rdata = ns_rr_rdata(rr);
        if(0==rdata) {
            break;
        }
        TXT.assign((const char*) rdata+1);
        TXTs.push_back(TXT);
    }
    return TXTs;
}

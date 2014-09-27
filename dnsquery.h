#ifndef DNSQUERY_H_INCLUDED
#define DNSQUERY_H_INCLUDED

#include <vector>
#include <string>
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>

#define N 4096


using namespace std;

vector<string> getTXTrecs(string domain, uint32_t maxTXTs);


#endif // DNSQUERY_H_INCLUDED

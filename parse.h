#ifndef PARSE_H_INCLUDED
#define PARSE_H_INCLUDED

#include <vector>
#include <string>

using namespace std;

typedef struct keyval_s
{
    string key;
    string val;
} keyval_t;

vector<keyval_t> txtrecstrparse(string txtstr);

#endif // PARSE_H_INCLUDED
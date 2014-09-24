#ifndef DATA_H_INCLUDED
#define DATA_H_INCLUDED

#include <vector>
#include <string>
#include "parse.h"

using namespace std;

typedef enum entrytype_e
{
    NO_ETYPE  = 0,
    PHONE_NR  = 1,
    EMAIL     = 2,
    ICQ       = 3,
    JABBER    = 4,

    ETYPE_NOT_SPEC = -1

} entrytype_et;


typedef enum subtype_e
{
    NO_SUBTYPE = 0,
    FIXED      = 1,
    MOBILE     = 2,
    PORTABLE   = 3,
    SAT        = 4,

    SUBTYPE_NOT_SPEC = -1

} subtype_et;

typedef enum usagetype_e
{
    NO_USAGETYPE = 0,
    HOME         = 1,
    WORK         = 2,
    PRIVAT       = 3,
    PUBLIC       = 4,

    USAGETYPE_NOT_SPEC = -1


} usagetype_et;


typedef struct smartrns_data_entry_phone_s
{
    subtype_et subtype;
    usagetype_et usage;
    string country;
    string prefix;
    string number;
    string suffix;

} smartrns_data_entry_phone_t;

typedef struct smartrns_data_entry_email_s
{
    string email;

} smartrns_data_entry_email_t;

typedef struct smartrns_data_entry_icq_s
{
    uint64_t icq;

} smartrns_data_entry_icq_t;

typedef struct smartrns_data_entry_jabber_s
{
    string jabber;

} smartrns_data_entry_jabber_t;

typedef struct smartrns_data_entry_s
{
    string name;
    string comment;
    entrytype_et type;
    void* entry;

} smartrns_data_entry_t;

typedef struct smartrns_data_s
{
    string version;
    string name;
    string comment;
    vector<smartrns_data_entry_t> entries;

} smartrns_data_t;


entrytype_et str2entrytype(string str);
subtype_et str2subtype(string str);
usagetype_et str2usagetype(string str);
smartrns_data_t smartrnsvec2smartrnsdata(vector<keyval_t> smartrnsvec);
smartrns_data_t txtrec2smartrnsdata(u_char* txtrec);


#endif // DATA_H_INCLUDED

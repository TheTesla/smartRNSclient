
#include "data.h"

#include <iostream>


entrytype_et str2entrytype(string str)
{
    if("none" == str) return ETYPE_NOT_SPEC;
    if("phone" == str) return PHONE_NR;
    if("email" == str) return EMAIL;
    if("icq" == str) return ICQ;
    if("jabber" == str) return JABBER;
    return NO_ETYPE;
}

subtype_et str2subtype(string str)
{
    if("none" == str) return SUBTYPE_NOT_SPEC;
    if("fixed" == str) return FIXED;
    if("mobile" == str) return MOBILE;
    if("portable" == str) return PORTABLE;
    if("sat" == str) return SAT;
    return NO_SUBTYPE;
}

usagetype_et str2usagetype(string str)
{
    if("none" == str) return USAGETYPE_NOT_SPEC;
    if("home" == str) return HOME;
    if("work" == str) return WORK;
    if("privat" == str) return PRIVAT;
    if("public" == str) return PUBLIC;

    return NO_USAGETYPE;
}

smartrns_data_t smartrnsvec2smartrnsdata(vector<keyval_t> smartrnsvec)
{
    smartrns_data_t data;
    smartrns_data_entry_t entry;
    smartrns_data_entry_phone_t phone;
    smartrns_data_entry_email_t email;
    smartrns_data_entry_icq_t icq;
    smartrns_data_entry_jabber_t jabber;
    uint32_t i;

    for(i=0;i<smartrnsvec.size();i++){
        if("smartrns.data.version" == smartrnsvec[i].key){
            data.version = smartrnsvec[i].val;
        }else if("smartrns.data.comment" == smartrnsvec[i].key){
            data.comment = smartrnsvec[i].val;
        }else if("smartrns.data.name" == smartrnsvec[i].key){
            data.name = smartrnsvec[i].val;
        }else if("smartrns.data.entry.name" == smartrnsvec[i].key){
            entry.name = smartrnsvec[i].val;
        }else if("smartrns.data.entry.comment" == smartrnsvec[i].key){
            entry.comment = smartrnsvec[i].val;
        }else if("smartrns.data.entry.type" == smartrnsvec[i].key){
            entry.type = str2entrytype(smartrnsvec[i].val);
        }else if("smartrns.data.entry.country" == smartrnsvec[i].key){
            phone.country = smartrnsvec[i].val;
        }else if("smartrns.data.entry.prefix" == smartrnsvec[i].key){
            phone.prefix = smartrnsvec[i].val;
        }else if("smartrns.data.entry.number" == smartrnsvec[i].key){
            phone.number = smartrnsvec[i].val;
        }else if("smartrns.data.entry.suffix" == smartrnsvec[i].key){
            phone.suffix = smartrnsvec[i].val;
        }else if("smartrns.data.entry.usage" == smartrnsvec[i].key){
            phone.usage = str2usagetype(smartrnsvec[i].val);
        }else if("smartrns.data.entry.subtype" == smartrnsvec[i].key){
            phone.subtype = str2subtype(smartrnsvec[i].val);
        }else if("smartrns.data.entry.email" == smartrnsvec[i].key){
            email.email = smartrnsvec[i].val;
        }else if("smartrns.data.entry.icq" == smartrnsvec[i].key){
            icq.icq = atoll(smartrnsvec[i].val.c_str());
        }else if("smartrns.data.entry.jabber" == smartrnsvec[i].key){
            jabber.jabber = smartrnsvec[i].val;
        }else if("smartrns.data.entry.push" == smartrnsvec[i].key){
            if("1" == smartrnsvec[i].val){
                if(PHONE_NR == entry.type){
                    entry.entry = (void*) new smartrns_data_entry_phone_t;
                    cout << "phone" << endl;
                    *((smartrns_data_entry_phone_t*) entry.entry) = phone;
                }else if(EMAIL == entry.type){
                    entry.entry = (void*) new smartrns_data_entry_email_t;
                    cout << "email" << endl;
                    *((smartrns_data_entry_email_t*) entry.entry) = email;
                }else if(ICQ == entry.type){
                    entry.entry = (void*) new smartrns_data_entry_icq_t;
                    cout << "icq" << endl;
                    *((smartrns_data_entry_icq_t*) entry.entry) = icq;
                }else if(JABBER == entry.type){
                    entry.entry = (void*) new smartrns_data_entry_jabber_t;
                    cout << "jabber" << endl;
                    *((smartrns_data_entry_jabber_t*) entry.entry) = jabber;
                }
                data.entries.push_back(entry);
            }

        }

        cout << smartrnsvec[i].key << " " << smartrnsvec[i].val << endl;
    }

    return data;
}


smartrns_data_t txtrec2smartrnsdata(u_char* txtrec)
{
    vector<keyval_t> smartrnsvec;
    string txt, txtstr;

    txt.assign((const char*)txtrec);
    txtstr = txt.substr(1); // delete length-entry

    smartrnsvec = txtrecstrparse(txtstr);

    return smartrnsvec2smartrnsdata(smartrnsvec);
}

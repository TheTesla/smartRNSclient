
#include "parse.h"

vector<keyval_t> txtrecstrparse(string txtstr)
{
    vector<keyval_t> smartrnsvec;
    keyval_t elem;
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
                elem.key = keysstr + key; // build complete variable name and save to key-value-pair
                elem.val = val; // ... add the value
                smartrnsvec.push_back(elem);
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

    return smartrnsvec;

}

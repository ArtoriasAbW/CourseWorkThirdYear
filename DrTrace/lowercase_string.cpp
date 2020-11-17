#include "lowercase_string.h"

std::string str_to_lowercase(char *str)
{
    size_t len = strlen(str);
    std::string ret;
    ret.reserve(len);

    for (int i = 0; i < len; i++) {
        ret += tolower(str[i]);
    }

    return ret;
}

std::string str_to_lowercase(std::string str)
{
    size_t len = str.length();
    std::string ret;
    ret.reserve(len);

    for (int i = 0; i < len; i++) {
        ret += tolower(str[i]);
    }

    return ret;
}
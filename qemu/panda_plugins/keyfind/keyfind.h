/* PANDABEGINCOMMENT PANDAENDCOMMENT */
#pragma once
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

// for htons
#include <arpa/inet.h>

#include <algorithm>
#include <string>
#include <fstream>
#include <sstream>
#include <algorithm> 
#include <functional> 
#include <cctype>
#include <locale>

// trim from start
static inline std::string &ltrim(std::string &s) {
        s.erase(s.begin(), std::find_if(s.begin(), s.end(), std::not1(std::ptr_fun<int, int>(std::isspace))));
        return s;
}

// trim from end
static inline std::string &rtrim(std::string &s) {
        s.erase(std::find_if(s.rbegin(), s.rend(), std::not1(std::ptr_fun<int, int>(std::isspace))).base(), s.end());
        return s;
}

// trim from both ends
static inline std::string &trim(std::string &s) {
        return ltrim(rtrim(s));
}

typedef struct _StringInfo {
    unsigned char* data;
    unsigned int data_len;
} StringInfo;

void ssl_print_data(const char* name, const unsigned char* data, size_t len);

void ssl_print_string(const char* name, const StringInfo* data);

int ssl_data_alloc(StringInfo* str, size_t len);

int tls_prf(StringInfo* secret, const char *usage,
    StringInfo* rnd1, StringInfo* rnd2, StringInfo* out);

int tls12_prf(const EVP_MD *md, StringInfo* secret, const char* usage,
    StringInfo* rnd1, StringInfo* rnd2, StringInfo* out);

// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

/* Copyright 2015 Linaro Ltd
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "jsmn.h"
#include "JSONWebKey.h"

#include <algorithm>
#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_JSON_TOKENS 2048
#define MAX_KEY_SIZE  2048
#define MAX_KEY_ID_SIZE  2048

namespace media{
/* 
   Base64 decoder based on: base64.cpp and base64.h

   Copyright (C) 2004-2008 René Nyffenegger

   This source code is provided 'as-is', without any express or implied
   warranty. In no event will the author be held liable for any damages
   arising from the use of this software.

   Permission is granted to anyone to use this software for any purpose,
   including commercial applications, and to alter it and redistribute it
   freely, subject to the following restrictions:

   1. The origin of this source code must not be misrepresented; you must not
      claim that you wrote the original source code. If you use this source code
      in a product, an acknowledgment in the product documentation would be
      appreciated but is not required.

   2. Altered source versions must be plainly marked as such, and must not be
      misrepresented as being the original source code.

   3. This notice may not be removed or altered from any source distribution.

   René Nyffenegger rene.nyffenegger@adp-gmbh.ch

*/
const std::string Base64Chars =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789+/";

inline bool IsBase64(unsigned char c) {
    return (isalnum(c) || (c == '+') || (c == '/'));
}

std::string Base64Encode(char const* bytesToEncode, unsigned int len) {
    std::string ret;
    int i = 0;
    int j = 0;
    unsigned char charArray3[3];
    unsigned char charArray4[4];

    while (len--) {
        charArray3[i++] = *(bytesToEncode++);
        if (i == 3) {
            charArray4[0] = (charArray3[0] & 0xfc) >> 2;
            charArray4[1] = ((charArray3[0] & 0x03) << 4) + ((charArray3[1] & 0xf0) >> 4);
            charArray4[2] = ((charArray3[1] & 0x0f) << 2) + ((charArray3[2] & 0xc0) >> 6);
            charArray4[3] = charArray3[2] & 0x3f;

            for(i = 0; (i <4) ; i++)
                ret += Base64Chars[charArray4[i]];
            i = 0;
        }
    }

    if (i)
    {
        for(j = i; j < 3; j++)
            charArray3[j] = '\0';

        charArray4[0] = ( charArray3[0] & 0xfc) >> 2;
        charArray4[1] = ((charArray3[0] & 0x03) << 4) + ((charArray3[1] & 0xf0) >> 4);
        charArray4[2] = ((charArray3[1] & 0x0f) << 2) + ((charArray3[2] & 0xc0) >> 6);

        for (j = 0; (j < i + 1); j++)
            ret += Base64Chars[charArray4[j]];
    }

    return ret;

}

std::string Base64Decode(std::string const& encodedString) {
    int len = encodedString.size();
    int i = 0;
    int j = 0;
    int it = 0;
    unsigned char charArray4[4], charArray3[3];
    std::string ret;

    while (len-- && ( encodedString[it] != '=') && IsBase64(encodedString[it])) {
        charArray4[i++] = encodedString[it]; it++;
        if (i ==4) {
            for (i = 0; i <4; i++)
                charArray4[i] = Base64Chars.find(charArray4[i]);

            charArray3[0] = (charArray4[0] << 2) + ((charArray4[1] & 0x30) >> 4);
            charArray3[1] = ((charArray4[1] & 0xf) << 4) + ((charArray4[2] & 0x3c) >> 2);
            charArray3[2] = ((charArray4[2] & 0x3) << 6) + charArray4[3];

            for (i = 0; (i < 3); i++)
                ret += charArray3[i];
            i = 0;
        }
    }

    if (i) {
        for (j = i; j <4; j++)
            charArray4[j] = 0;

        for (j = 0; j <4; j++)
            charArray4[j] = Base64Chars.find(charArray4[j]);

        charArray3[0] = (charArray4[0] << 2) + ((charArray4[1] & 0x30) >> 4);
        charArray3[1] = ((charArray4[1] & 0xf) << 4) + ((charArray4[2] & 0x3c) >> 2);
        charArray3[2] = ((charArray4[2] & 0x3) << 6) + charArray4[3];

        for (j = 0; (j < i - 1); j++) ret += charArray3[j];
    }
    return ret;
}


/* Checks equality of two JSON string with a char. Returns 0 if strings are
 * equal. */
int JsonEq(const char *json, jsmntok_t *tok, const char *s) {
    if (tok->type == JSMN_STRING && (int) strlen(s) == tok->end - tok->start &&
            strncmp(json + tok->start, s, tok->end - tok->start) == 0) {
        return 0;
    }
    return -1;
}

void FixUpURLSafeBase64(std::string &str)
{
    std::replace(str.begin(), str.end(), '_', '/');
    std::replace(str.begin(), str.end(), '-', '+');
}

bool ConvertStringsToKeyPair(KeyIdAndKeyPairs& keys, std::string key,
    std::string keyId)
{
    size_t padding;
    std::string decodedKey, decodedKeyId;
    /* Chromium removes the padding strings from the B64 strings. We need
     * to append them for compatibility with the B64 parsers */
    padding = keyId.length()%4;

    if(padding > 0)
        keyId.append(padding, kBase64Padding);

    padding = key.length()%4;
    if(padding > 0)
        key.append(padding, kBase64Padding);

    FixUpURLSafeBase64(key);
    FixUpURLSafeBase64(keyId);

    decodedKey = Base64Decode(key);
    decodedKeyId = Base64Decode(keyId);
    keys[decodedKeyId] = decodedKey;
    return true;
}

bool ExtractKeysFromJWKSet(const std::string& jwkSet,
    KeyIdAndKeyPairs& keys,
    int sessionType) {
    /*We expect max 128 tokens
     * FIXME: We need a different and safe JSON parser.
     */
    jsmntok_t t[MAX_JSON_TOKENS];
    jsmn_parser parser;
    int result;
    const char* jchr  = &(jwkSet.c_str()[0]);

    std::string algorithm;
    std::string key;
    std::string keyId;
    jsmn_init(&parser);
    result = jsmn_parse(&parser, jchr, jwkSet.size(), t, sizeof(t)/sizeof(t[0]));

    if(result<0) {
        std::cout << "Failed to parse JSON" << jwkSet << std::endl;
        return false;
    }

    if(JsonEq(jchr, &t[1], kKeysTag)!=0) {
        std::cout <<  "Unable to parse JSON. Expected kKeyTag : " << kKeysTag << std::endl;
        return false;
    }

    KeyIdAndKeyPairs local_keys;
    /* Ignore the first 2 tokens */
    for(int i = 2; i < result; i++) {
        if(JsonEq(jchr, &t[i], kAlgTag) == 0 && (i+1) < MAX_JSON_TOKENS) {
            algorithm = std::string(jchr + t[i+1].start, t[i+1].end - t[i+1].start);
            continue;
        }

        if(JsonEq(jchr, &t[i], kKeyTag) == 0 && (i+1) < MAX_JSON_TOKENS) {
            if(key.size() != 0) {
                std::cout << "CDMI supports only one key in JSON message. Got multiple keys." << std::endl;
                return false;
            }
            key = std::string(jchr + t[i+1].start, t[i+1].end - t[i+1].start);
            continue;
        }

        if(JsonEq(jchr, &t[i], kKeyIdTag) == 0 && (i+1) < MAX_JSON_TOKENS) {
            if(keyId.size() != 0) {
                std::cout << "CDMI supports only one keyID in JSON message. Got multiple keys." << std::endl;
                return false;
            }
            keyId = std::string(jchr + t[i+1].start, t[i+1].end - t[i+1].start);
            continue;
        }
    }
    ConvertStringsToKeyPair(keys, key, keyId);
    return true;
}
}

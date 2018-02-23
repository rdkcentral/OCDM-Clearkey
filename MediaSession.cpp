/*
 * Copyright 2014 Fraunhofer FOKUS
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

#include "MediaSession.h"
#include "json_web_key.h"
#include "keypairs.h"

#include <assert.h>
#include <iostream>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <pthread.h>
#include <sstream>
#include <string>
#include <string.h>

#define DESTINATION_URL_PLACEHOLDER "http://no-valid-license-server"
#define NYI_KEYSYSTEM "keysystem-placeholder"
#define K_DECRYPTION_KEY_SIZE 16

using namespace std;

namespace CDMi {

static media::KeyIdAndKeyPairs g_keys;
uint32_t MediaKeySession::s_sessionCnt = 10;


static void hex_print(const void *pv, size_t len) {
  const unsigned char *p = (const unsigned char*)pv;
  if (!pv)
    printf("NULL");
  else
  {
    size_t i = 0;
    for (; i<len; ++i)
      printf("%02X ", *p++);
  }
  printf("\n");
}

static std::string keyIdAndKeyPairsToJSON(media::KeyIdAndKeyPairs *g_keys) {
  /* FIXME: This JSON consturctor is for proof of concept only.
  * We need to add a proper JSON library.
  */
  ostringstream result;
  result << "{ ";
  for (std::vector<media::KeyIdAndKeyPair>::iterator it = g_keys->begin(); it != g_keys->end(); ++it)
  {
    result <<  "\""  << it->first  << "\" : \"" << MEDIA_KEY_STATUS_USABLE << "\"\n";
  }
  result  << "}";
  return result.str();
}

const char* MediaKeySession::CreateSessionId() {
  const char *tmp;
  stringstream strs;
  strs << s_sessionCnt;
  string tmp_str = strs.str();
  tmp = tmp_str.c_str();

  char *buffer = new char[tmp_str.length()]();
  strcpy(buffer, tmp);

  s_sessionCnt += 1;

  return const_cast<char*>(buffer);
}

MediaKeySession::MediaKeySession(void) {
  m_sessionId = MediaKeySession::CreateSessionId();
  cout << "creating mediakeysession with id: " << m_sessionId << endl;
}

MediaKeySession::~MediaKeySession(void) {}

void MediaKeySession::Run(const IMediaKeySessionCallback *f_piMediaKeySessionCallback) {
  int ret;
  pthread_t thread;

  cout << "#mediakeysession.Run" << endl;

  if (f_piMediaKeySessionCallback) {
    m_piCallback = const_cast<IMediaKeySessionCallback*>(f_piMediaKeySessionCallback);

    ret = pthread_create(&thread, nullptr, MediaKeySession::_CallRunThread, this);
    if (ret == 0) {
      pthread_detach(thread);
    } else {
      cout << "#mediakeysession.Run: err: could not create thread" << endl;
      return;
    }
  } else {
    cout << "#mediakeysession.Run: err: MediaKeySessionCallback NULL?" << endl;
  }
}

void* MediaKeySession::_CallRunThread(void *arg) {
  return ((MediaKeySession*)arg)->RunThread(1);
}

void* MediaKeySession::_CallRunThread2(void *arg) {
  return ((MediaKeySession*)arg)->RunThread(2);
}

void* MediaKeySession::RunThread(int f_i) {
  cout << "#mediakeysession._RunThread" << endl;
  const char *message = "stub-message";
  if (f_i == 1) {
    m_piCallback->OnKeyMessage((const uint8_t*)message, strlen(message), const_cast<char*>(DESTINATION_URL_PLACEHOLDER));
  } else {
    m_piCallback->OnKeyReady();
  }
}

CDMi_RESULT MediaKeySession::Load(void) {
  return CDMi_S_FALSE;
}

void MediaKeySession::Update(
    const uint8_t *f_pbKeyMessageResponse,
    uint32_t f_cbKeyMessageResponse) {
  int ret;
  pthread_t thread;
  std::string keys_updated;

  cout << "#mediakeysession.Run" << endl;
  std::string key_string(reinterpret_cast<const char*>(f_pbKeyMessageResponse), f_cbKeyMessageResponse);
  // Session type is set to "0". We keep the function signature to
  // match Chromium's ExtractKeysFromJWKSet(...) function
  media::ExtractKeysFromJWKSet(key_string, &g_keys, 0);

  ret = pthread_create(&thread, NULL, MediaKeySession::_CallRunThread2, this);
  if (!ret) {
    pthread_detach(thread);
  } else {
    cout << "#mediakeysession.Run: err: could not create thread" << endl;
    return;
  }
  keys_updated = keyIdAndKeyPairsToJSON(&g_keys);
  m_piCallback->OnKeyStatusUpdate(keys_updated.data());
}

CDMi_RESULT MediaKeySession::Remove(void) {
  return CDMi_S_FALSE;
}

CDMi_RESULT MediaKeySession::Close(void) {}

const char* MediaKeySession::GetSessionId(void) const {
  cout <<"Inside GetSessionId"<< endl;
  return m_sessionId;
}

const char* MediaKeySession::GetKeySystem(void) const {
  // FIXME:(fhg):
  return NYI_KEYSYSTEM;
}

CDMi_RESULT MediaKeySession::Init(
    int32_t licenseType,
    const char *f_pwszInitDataType,
    const uint8_t *f_pbInitData,
    uint32_t f_cbInitData,
    const uint8_t *f_pbCDMData,
    uint32_t f_cbCDMData) {
  return CDMi_SUCCESS;
}

CDMi_RESULT MediaKeySession::Decrypt(
    const uint8_t *f_pbSessionKey,
    uint32_t f_cbSessionKey,
    const uint32_t *f_pdwSubSampleMapping,
    uint32_t f_cdwSubSampleMapping,
    const uint8_t *f_pbIV,
    uint32_t f_cbIV,
    const uint8_t *f_pbData,
    uint32_t f_cbData,
    uint32_t *f_pcbOpaqueClearContent,
    uint8_t **f_ppbOpaqueClearContent) {
  AES_KEY aes_key;
  uint8_t *out; /* Faked secure buffer */
  const char *key;

  cout << "Inside MediaKeySession::Decrypt "<< endl;
  uint8_t ivec[AES_BLOCK_SIZE] = { 0 };
  uint8_t ecount_buf[AES_BLOCK_SIZE] = { 0 };
  unsigned int block_offset = 0;


  assert(f_cbIV <  AES_BLOCK_SIZE);

  if (!f_pcbOpaqueClearContent) {
    cout << "ERROR: f_pcbOpaqueClearContent is NULL" << endl;
    return -1;
  }

  out = (uint8_t*) malloc(f_cbData * sizeof(uint8_t));

  if (g_keys.size() != 1) {
    cout << "FIXME: We support only one key at the moment. Number keys: " << g_keys.size()<< endl;
  }

  if ( (g_keys[0].second).size() != K_DECRYPTION_KEY_SIZE) {
    cout << "ERROR: Wrong key size" << endl;
    goto fail;
  }

  key = (g_keys[0].second).data();

  AES_set_encrypt_key(reinterpret_cast<const unsigned char*>(key), strlen(key) * 8, &aes_key);

  memcpy(&(ivec[0]), f_pbIV, f_cbIV);

  AES_ctr128_encrypt(reinterpret_cast<const unsigned char*>(f_pbData), out, f_cbData, &aes_key, ivec, ecount_buf, &block_offset);

  /* Return clear content */
  *f_pcbOpaqueClearContent = f_cbData;
  *f_ppbOpaqueClearContent = out;

  return CDMi_SUCCESS;
fail:
   free(out);
   return -1;
}

CDMi_RESULT MediaKeySession::ReleaseClearContent(
    const uint8_t *f_pbSessionKey,
    uint32_t f_cbSessionKey,
    const uint32_t  f_cbClearContentOpaque,
    uint8_t  *f_pbClearContentOpaque ){
  free(f_pbClearContentOpaque);
}
}  // namespace CDMi

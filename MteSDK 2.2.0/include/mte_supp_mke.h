/*
Copyright (c) Eclypses, Inc.

All rights reserved.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/
#ifndef mte_supp_mke_h
#define mte_supp_mke_h

#ifndef mte_base_h
#include "mte_base.h"
#endif

/* This is a support wrapper around the Managed-Key Encryption add-on to handle
   memory allocation.

   To use with a Windows DLL, compile with MTE_BUILD_SHARED defined.

   To create an encoder/encryptor:
   1. Call mte_supp_mke_enc_alloc() to create a new encoder/encryptor. The
      returned encoder/encryptor must be freed with mte_supp_mke_enc_free()
      when you are done with it.
   2. Initialize:
      a. mte_mke_enc_instantiate() [using entropy, nonce, personalization]
      b. mte_mke_enc_state_restore() [using saved state (see below)]

   To save/restore an encoder/encryptor:
   1. Call:
      a. mte_supp_mke_enc_state_save() [raw]
      b. mte_supp_mke_enc_state_save_b64() [Base64-encoded]
      to save the state to a buffer. The returned saved state must be freed
      with mte_supp_buff_free() when you are done with it. For security, it is
      recommended to zero the saved state before freeing it.
   2. Call mte_mke_enc_state_restore() to instantiate an encoder/encryptor from
      saved state. For security, it is recommended to zero the saved state
      after restoring.

   To use an encoder/encryptor:
   1. Encode/encrypt each message:
      a. mte_supp_mke_enc_encode() [raw]
      b. mte_supp_mke_enc_encode_b64() [Base64-encoded]
      The returned encoded/encrypted version must be freed with
      mte_supp_buff_free() when you are done with it. The encoded_bytes will be
      set to the encoded length. Exactly this length must be given to the
      decoder/decryptor to decode successfully.

   To destroy an encoder/encryptor:
   1. Call mte_supp_mke_enc_free(). This will zero the state of the encoder/
      encryptor for security and release allocated resources.

   To create a decoder/decryptor:
   1. Call mte_supp_mke_dec_alloc() to create a new decoder/decryptor. The
      returned decoder/decryptor must be freed with mte_supp_mke_dec_free()
      when you are done with it.
   2. Initialize:
      a. mte_mke_dec_instantiate() [using entropy, nonce, personalization]
      b. mte_mke_dec_state_restore() [using saved state (see below)]

   To save/restore a decoder/decryptor:
   1. Call:
      a. mte_supp_mke_dec_state_save() [raw]
      b. mte_supp_mke_dec_state_save_b64() [Base64-encoded]
      to save the state to a buffer. The returned saved state must be freed
      with mte_supp_buff_free() when you are done with it. For security, it is
      recommended to zero the saved state before freeing it.
   2. Call mte_mke_dec_state_restore() to instantiate a decoder/decryptor from
      saved state. For security, it is recommended to zero the saved state
      after restoring.

   To use a decoder/decryptor:
   1. Decode/decrypt each message:
      a. mte_supp_mke_dec_decode() [raw]
      b. mte_supp_mke_dec_decode_b64() [Base64-encoded]
      The returned decoded/decrypted version must be freed with
      mte_supp_buff_free() when you are done with it. The decoded_bytes will be
      set to the decoded length.
   2. The encode timestamp is retrieved with mte_mke_dec_enc_ts().
   3. The decode timestamp is retrieved with mte_mke_dec_dec_ts().
   4. The number of messages skipped is retrieved with
      mte_mke_dec_msg_skipped().

   To destroy a decoder/decryptor:
   1. Call mte_supp_mke_dec_free(). This will zero the state of the decoder/
      decryptor for security and release allocated resources.
*/
#ifdef __cplusplus
extern "C"
{
#endif

/* Create an encoder/encryptor given the DRBG algorithm, token size in bytes,
   verifiers algorithm, and cipher/hash algorithms. Returns a handle to the
   encoder on success or NULL on failure. You must call mte_supp_mke_enc_free()
   when you are done with the encoder. */
MTE_SHARED
MTE_HANDLE mte_supp_mke_enc_alloc(mte_drbgs drbg,
                                  uint32_t tok_bytes,
                                  mte_verifiers verifiers,
                                  mte_ciphers cipher,
                                  mte_hashes hash);

/* Save the encoder/encryptor state. Returns the saved state and sets *bytes to
   the length of the saved state or NULL on failure. You must call
   mte_supp_buff_free() when you are done with the saved state. */
MTE_SHARED
void *mte_supp_mke_enc_state_save(MTE_CHANDLE encoder, uint32_t *bytes);
MTE_SHARED
char *mte_supp_mke_enc_state_save_b64(MTE_CHANDLE encoder, uint32_t *bytes);

/* Encode/encrypt the given data of the given byte length in raw form. Returns
   the encoded version on success or NULL on failure. Sets *encoded_bytes to the
   encoded version length in bytes. Sets *status to the status. The encoded
   version is valid only if *status is mte_status_success. You must call
   mte_supp_buff_free() when you are done with the encoded/encrypted version.

   The timestamp callback and context are used to obtain the timestamp if the
   timestamp verifier is enabled. */
MTE_SHARED
void *mte_supp_mke_enc_encode(MTE_HANDLE encoder,
                              mte_verifier_get_timestamp64 t_cb,
                              void *t_cb_context,
                              const void *data,
                              uint32_t data_bytes,
                              uint32_t *encoded_bytes,
                              mte_status *status);

/* Encode/encrypt the given data of the given byte length in Base64 form.
   Returns the encoded version on success or NULL on failure. Sets
   *encoded_bytes to the encoded version length in bytes. Sets *status to the
   status. The encoded version is valid only if *status is mte_status_success.
   You must call mte_supp_buff_free() when you are done with the encoded/
   encrypted version.

   The timestamp callback and context are used to obtain the timestamp if the
   timestamp verifier is enabled. */
MTE_SHARED
char *mte_supp_mke_enc_encode_b64(MTE_HANDLE encoder,
                                  mte_verifier_get_timestamp64 t_cb,
                                  void *t_cb_context,
                                  const void *data,
                                  uint32_t data_bytes,
                                  uint32_t *encoded_bytes,
                                  mte_status *status);

/* Free an encoder/encryptor allocated with mte_supp_mke_enc_alloc(). The state
   of the encoder/encryptor is first zeroed for security. Returns the status. */
MTE_SHARED
mte_status mte_supp_mke_enc_free(MTE_HANDLE encoder);

/* Create a decoder/decryptor given the DRBG algorithm, token size in bytes,
   verifiers algorithm, cipher/hash algorithms, timestamp window, and sequence
   window. Returns a handle to the decoder on success or NULL on failure. You
   must call mte_supp_mke_dec_free() when you are done with the decoder. */
MTE_SHARED
MTE_HANDLE mte_supp_mke_dec_alloc(mte_drbgs drbg,
                                  uint32_t tok_bytes,
                                  mte_verifiers verifiers,
                                  mte_ciphers cipher,
                                  mte_hashes hash,
                                  uint64_t t_window,
                                  int32_t s_window);

/* Save the decoder/decryptor state. Returns the saved state and sets *bytes to
   the length of the saved state or NULL on failure. You must call
   mte_supp_buff_free() when you are done with the saved state. */
MTE_SHARED
void *mte_supp_mke_dec_state_save(MTE_CHANDLE decoder, uint32_t *bytes);
MTE_SHARED
char *mte_supp_mke_dec_state_save_b64(MTE_CHANDLE decoder, uint32_t *bytes);

/* Decode/decrypt the given raw encoded data of the given byte length. Returns
   the decoded version. Sets *decoded_bytes to the decoded version length in
   bytes. Sets *status to the status. The decoded/decrypted version is valid
   only if !mte_base_status_is_error(*status). You must call
   mte_supp_buff_free() when you are done with the decoded/decrypted version.

   The timestamp callback and context are used to obtain the timestamp if the
   timestamp verifier is enabled. */
MTE_SHARED
void *mte_supp_mke_dec_decode(MTE_HANDLE decoder,
                              mte_verifier_get_timestamp64 t_cb,
                              void *t_cb_context,
                              const void *encoded,
                              uint32_t encoded_bytes,
                              uint32_t *decoded_bytes,
                              mte_status *status);

/* Decode/decrypt the given Base64-encoded encoded/encrypted data of the given
   byte length. Returns the decoded version. Sets *decoded_bytes to the decoded
   version length in bytes. Sets *status to the status. The decoded version is
   valid only if !mte_base_status_is_error(*status). You must call
   mte_supp_buff_free() when you are done with the decoded/decrypted version.

   The timestamp callback and context are used to obtain the timestamp if the
   timestamp verifier is enabled. */
MTE_SHARED
void *mte_supp_mke_dec_decode_b64(MTE_HANDLE decoder,
                                  mte_verifier_get_timestamp64 t_cb,
                                  void *t_cb_context,
                                  const void *encoded,
                                  uint32_t encoded_bytes,
                                  uint32_t *decoded_bytes,
                                  mte_status *status);

/* Free a decoder/decryptor allocated with mte_supp_mke_dec_alloc(). The state
   of the decoder/decryptor is first zeroed for security. Returns the status. */
MTE_SHARED
mte_status mte_supp_mke_dec_free(MTE_HANDLE decoder);

#ifdef __cplusplus
}
#endif

#endif


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
#ifndef mte_wrap_mke_enc_h
#define mte_wrap_mke_enc_h

#ifndef mte_wrap_base_h
#include "mte_wrap_base.h"
#endif

/* This wraps the MTE Managed-Key Encryption add-on encoder functions.

   To use with a dynamic library, compile with MTE_BUILD_SHARED defined.
*/
#ifdef __cplusplus
extern "C"
{
#endif

/* Returns the encoder state size for the given DRBG algorithm, token size in
   bytes, verifiers algorithm, and cipher/hash algorithms. Returns 0 if the
   combination is not usable. */
MTE_SHARED
MTE_UINT32_T mte_wrap_mke_enc_state_bytes(mte_drbgs drbg,
                                          MTE_UINT32_T tok_bytes,
                                          mte_verifiers verifiers,
                                          mte_ciphers cipher,
                                          mte_hashes hash);

/* Initialize the encoder state given the DRBG algorithm, token size in bytes,
   verifiers algorithm, and cipher/hash algorithms. Returns the status.

   The state buffer must be of sufficient length to hold the encoder state. See
   mte_wrap_mke_enc_state_bytes(). */
MTE_SHARED
mte_status mte_wrap_mke_enc_state_init(MTE_HANDLE state,
                                       mte_drbgs drbg,
                                       MTE_UINT32_T tok_bytes,
                                       mte_verifiers verifiers,
                                       mte_ciphers cipher,
                                       mte_hashes hash);

/* Instantiate the encoder given the entropy input callback/context, nonce
   callback/context, personalization string, and length of the personalization
   string in bytes. Returns the status. */
MTE_SHARED
mte_status mte_wrap_mke_enc_instantiate(MTE_HANDLE state,
                                        mte_wrap_get_entropy_input ei_cb,
                                        void *ei_cb_context,
                                        mte_wrap_get_nonce n_cb,
                                        void *n_cb_context,
                                        const void *ps, MTE_UINT32_T ps_bytes);

/* Returns the state save size [raw]. Returns 0 if save is unsupported. */
MTE_SHARED
MTE_UINT32_T mte_wrap_mke_enc_save_bytes(MTE_CHANDLE state);

/* Returns the state save size [Base64-encoded]. Returns 0 if save is
   unsupported. */
MTE_SHARED
MTE_UINT32_T mte_wrap_mke_enc_save_bytes_b64(MTE_CHANDLE state);

/* Save the encoder state to the given buffer encoded in Base64. The size of
   the buffer must be mte_wrap_mke_enc_save_bytes_b64() and the result is null-
   terminated. Returns mte_status_unsupported if not supported; otherwise
   returns mte_status_success. */
MTE_SHARED
mte_status mte_wrap_mke_enc_state_save_b64(MTE_CHANDLE state, void *saved);

/* Restore the encoder state from the given buffer in raw form. Returns
   mte_status_unsupported if not supported; otherwise returns
   mte_status_success. */
MTE_SHARED
mte_status mte_wrap_mke_enc_state_restore_b64(MTE_HANDLE state,
                                              const void *saved);

/* Returns the encode buffer size [raw] in bytes given the data length in bytes.
   The encode buffer provided to mte_wrap_mke_enc_encode() must be of at least
   this length. */
MTE_SHARED
MTE_UINT32_T mte_wrap_mke_enc_buff_bytes(MTE_CHANDLE state,
                                         MTE_UINT32_T data_bytes);

/* Returns the encode buffer size [Base64-encoded] in bytes given the data
   length in bytes. The encode buffer provided to mte_wrap_mke_enc_encode_b64()
   must be of at least this length. */
MTE_SHARED
MTE_UINT32_T mte_wrap_mke_enc_buff_bytes_b64(MTE_CHANDLE state,
                                             MTE_UINT32_T data_bytes);

/* Encode the given data of the given byte length to the given encode buffer in
   raw form. Returns the status. Sets *encoded_off to the offset in the encoded
   buffer where the encoded version can be found and sets *encoded_bytes to the
   raw encoded version length in bytes. The encoded version is valid only if
   mte_status_success is returned.

   The timestamp callback and context are used to obtain the timestamp if the
   timestamp verifier is enabled.

   The encoded buffer must be of sufficient length to hold the encoded version.
   See mte_wrap_mke_enc_buff_bytes(). */
MTE_SHARED
mte_status mte_wrap_mke_enc_encode(MTE_HANDLE state,
                                   mte_verifier_get_timestamp64 t_cb,
                                   void *t_cb_context,
                                   const void *data, MTE_UINT32_T data_bytes,
                                   void *encoded,
                                   MTE_UINT32_T *encoded_off,
                                   MTE_UINT32_T *encoded_bytes);

/* Encode the given data of the given byte length to the given encode buffer,
   encoded in Base64. Returns the status. Sets *encoded_off to the offset in
   the encoded buffer where the Base64 version can be found and sets
   *encoded_bytes to the Base64-encoded version length in bytes. The encoded
   version is null terminated, but *encoded_bytes excludes the null terminator.
   The encoded version is valid only if mte_status_success is returned.

   The timestamp callback and context are used to obtain the timestamp if the
   timestamp verifier is enabled.

   The encoded buffer must be of sufficient length to hold the encoded version.
   See mte_wrap_mke_enc_buff_bytes_b64(). */
MTE_SHARED
mte_status mte_wrap_mke_enc_encode_b64(MTE_HANDLE state,
                                       mte_verifier_get_timestamp64 t_cb,
                                       void *t_cb_context,
                                       const void *data,
                                       MTE_UINT32_T data_bytes,
                                       void *encoded,
                                       MTE_UINT32_T *encoded_off,
                                       MTE_UINT32_T *encoded_bytes);

/* Returns the length of the result mte_wrap_mke_enc_encrypt_finish() will
   produce. Use this if you need to know that size before you can call it. */
MTE_SHARED
MTE_UINT32_T mte_wrap_mke_enc_encrypt_finish_bytes(MTE_CHANDLE state);

/* Returns the chunk-based encryption state size in bytes. The c_state buffer
   provided to the mte_wrap_mke_enc_encrypt_*() functions must be of at least
   this length. */
MTE_SHARED
MTE_UINT32_T mte_wrap_mke_enc_encrypt_state_bytes(MTE_CHANDLE state);

/* Encrypt a chunk of data in a chunk-based encryption session. The data_bytes
   argument must be a multiple of the cipher block size being used. This means
   you must either choose a cipher with block size of 1 or perform your own
   padding. Returns the status.

   The encrypted buffer must be at least data_bytes in length to hold
   the encrypted version. The encrypted buffer may be the same as the data
   buffer to overwrite the data with the encrypted version. The encrypted
   version length is data_bytes. */
MTE_SHARED
mte_status mte_wrap_mke_enc_encrypt_chunk(MTE_HANDLE state, MTE_HANDLE c_state,
                                          const void *data,
                                          MTE_UINT32_T data_bytes,
                                          void *encrypted);

/* Finish the chunk-based encryption session. Returns the status. Writes the
   final part of the result to the c_state buffer and sets *result_off to the
   offset in the c_state buffer and sets *result_bytes to the length of this
   part of the result. The c_state is no longer usable for a chunk-based
   encryption session until mte_wrap_mke_enc_encrypt_start() is called.

   The timestamp callback and context are used to obtain the timestamp if the
   timestamp verifier is enabled. */
MTE_SHARED
mte_status mte_wrap_mke_enc_encrypt_finish(MTE_HANDLE state, MTE_HANDLE c_state,
                                           mte_verifier_get_timestamp64 t_cb,
                                           void *t_cb_context,
                                           MTE_UINT32_T *result_off,
                                           MTE_UINT32_T *result_bytes);

#ifdef __cplusplus
}
#endif

#endif


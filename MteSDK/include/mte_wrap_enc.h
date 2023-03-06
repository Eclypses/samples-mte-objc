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
#ifndef mte_wrap_enc_h
#define mte_wrap_enc_h

#ifndef mte_wrap_base_h
#include "mte_wrap_base.h"
#endif

/* This wraps the MTE encoder functions.

   To use with a dynamic library, compile with MTE_BUILD_SHARED defined.
*/
#ifdef __cplusplus
extern "C"
{
#endif

/* Returns the encoder state size for the given DRBG algorithm, token size in
   bytes, and verifiers algorithm. Returns 0 if the combination is not
   usable. */
MTE_SHARED
MTE_UINT32_T mte_wrap_enc_state_bytes(mte_drbgs drbg,
                                      MTE_UINT32_T tok_bytes,
                                      mte_verifiers verifiers);

/* Initialize the encoder state given the DRBG algorithm, token size in bytes,
   and verifiers algorithm. Returns the status.

   The state buffer must be of sufficient length to hold the encoder state. See
   mte_wrap_enc_state_bytes(). */
MTE_SHARED
mte_status mte_wrap_enc_state_init(MTE_HANDLE state,
                                   mte_drbgs drbg,
                                   MTE_UINT32_T tok_bytes,
                                   mte_verifiers verifiers);

/* Instantiate the encoder given the entropy input callback/context, nonce
   callback/context, personalization string, and length of the personalization
   string in bytes. Returns the status. */
MTE_SHARED
mte_status mte_wrap_enc_instantiate(MTE_HANDLE state,
                                    mte_wrap_get_entropy_input ei_cb,
                                    void *ei_cb_context,
                                    mte_wrap_get_nonce n_cb, void *n_cb_context,
                                    const void *ps, MTE_UINT32_T ps_bytes);

/* Returns the state save size [raw]. Returns 0 if save is unsupported. */
MTE_SHARED
MTE_UINT32_T mte_wrap_enc_save_bytes(MTE_CHANDLE state);

/* Returns the state save size [Base64-encoded]. Returns 0 if save is
   unsupported. */
MTE_SHARED
MTE_UINT32_T mte_wrap_enc_save_bytes_b64(MTE_CHANDLE state);

/* Save the encoder state to the given buffer encoded in Base64. The size of
   the buffer must be mte_wrap_enc_save_bytes_b64() and the result is null-
   terminated. Returns mte_status_unsupported if not supported; otherwise
   returns mte_status_success. */
MTE_SHARED
mte_status mte_wrap_enc_state_save_b64(MTE_CHANDLE state, void *saved);

/* Restore the encoder state from the given buffer in raw form. Returns
   mte_status_unsupported if not supported; otherwise returns
   mte_status_success. */
MTE_SHARED
mte_status mte_wrap_enc_state_restore_b64(MTE_HANDLE state, const void *saved);

/* Returns the encode buffer size [raw] in bytes given the data length in bytes.
   The encode buffer provided to mte_wrap_enc_encode() must be of at least this
   length. */
MTE_SHARED
MTE_UINT32_T mte_wrap_enc_buff_bytes(MTE_CHANDLE state,
                                     MTE_UINT32_T data_bytes);

/* Returns the encode buffer size [Base64-encoded] in bytes given the token
   size in bytes, verifiers algorithm, and data length in bytes. The encode
   buffer provided to mte_wrap_enc_encode_b64() must be of at least this
   length. */
MTE_SHARED
MTE_UINT32_T mte_wrap_enc_buff_bytes_b64(MTE_CHANDLE state,
                                         MTE_UINT32_T data_bytes);

/* Encode the given data of the given byte length to the given encode buffer in
   raw form. Returns the status. Sets *encoded_off to the offset in the encoded
   buffer where the encoded version can be found and sets *encoded_bytes to the
   raw encoded version length in bytes. The encoded version is valid only if
   mte_status_success is returned.

   The timestamp callback and context are used to obtain the timestamp if the
   timestamp verifier is enabled.

   The encoded buffer must be of sufficient length to hold the encoded version.
   See mte_wrap_enc_buff_bytes(). */
MTE_SHARED
mte_status mte_wrap_enc_encode(MTE_HANDLE state,
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
   See mte_wrap_enc_buff_bytes_b64(). */
MTE_SHARED
mte_status mte_wrap_enc_encode_b64(MTE_HANDLE state,
                                   mte_verifier_get_timestamp64 t_cb,
                                   void *t_cb_context,
                                   const void *data, MTE_UINT32_T data_bytes,
                                   void *encoded,
                                   MTE_UINT32_T *encoded_off,
                                   MTE_UINT32_T *encoded_bytes);

#ifdef __cplusplus
}
#endif

#endif


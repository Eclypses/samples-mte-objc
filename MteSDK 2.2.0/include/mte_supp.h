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
#ifndef mte_supp_h
#define mte_supp_h

#ifndef mte_base_h
#include "mte_base.h"
#endif

/* This is a support wrapper around the core API to handle memory allocation.

   To use with a Windows DLL, compile with MTE_BUILD_SHARED defined.

   To create an encoder:
   1. Call mte_supp_enc_alloc() to create a new encoder. The returned encoder
      must be freed with mte_supp_enc_free() when you are done with it.
   2. Initialize:
      a. mte_enc_instantiate() [using entropy, nonce, personalization]
      b. mte_enc_state_restore() [using saved state (see below)]

   To save/restore an encoder:
   1. Call:
      a. mte_supp_enc_state_save() [raw]
      b. mte_supp_enc_state_save_b64() [Base64-encoded]
      to save the state to a buffer. The returned saved state must be freed
      with mte_supp_buff_free() when you are done with it. For security, it is
      recommended to zero the saved state before freeing it.
   2. Call mte_enc_state_restore() to instantiate an encoder from saved state.
      For security, it is recommended to zero the saved state after restoring.

   To use an encoder:
   1. Encode each message:
      a. mte_supp_enc_encode() [raw]
      b. mte_supp_enc_encode_b64() [Base64-encoded]
      The returned encoded version must be freed with mte_supp_buff_free() when
      you are done with it. The encoded_bytes will be set to the encoded length.
      Exactly this length must be given to the decoder to decode successfully.

   To destroy an encoder:
   1. Call mte_supp_enc_free(). This will zero the state of the encoder for
      security and release allocated resources.

   To create a decoder:
   1. Call mte_supp_dec_alloc() to create a new decoder. The returned decoder
      must be freed with mte_supp_dec_free() when you are done with it.
   2. Initialize:
      a. mte_dec_instantiate() [using entropy, nonce, personalization]
      b. mte_dec_state_restore() [using saved state (see below)]

   To save/restore a decoder:
   1. Call:
      a. mte_supp_dec_state_save() [raw]
      b. mte_supp_dec_state_save_b64() [Base64-encoded]
      to save the state to a buffer. The returned saved state must be freed
      with mte_supp_buff_free() when you are done with it. For security, it is
      recommended to zero the saved state before freeing it.
   2. Call mte_dec_state_restore() to instantiate a decoder from saved state.
      For security, it is recommended to zero the saved state after restoring.

   To use a decoder:
   1. Decode each message:
      a. mte_supp_dec_decode() [raw]
      b. mte_supp_dec_decode_b64() [Base64-encoded]
      The returned decoded version must be freed with mte_supp_buff_free() when
      you are done with it. The decoded_bytes will be set to the decoded length.
   2. The encode timestamp is retrieved with mte_dec_enc_ts().
   3. The decode timestamp is retrieved with mte_dec_dec_ts().
   4. The number of messages skipped is retrieved with mte_dec_msg_skipped().

   To destroy a decoder:
   1. Call mte_supp_dec_free(). This will zero the state of the decoder for
      security and release allocated resources.
*/
#ifdef __cplusplus
extern "C"
{
#endif

/* Create an encoder given the DRBG algorithm, token size in bytes, and
   verifiers algorithm. Returns a handle to the encoder on success or NULL
   on failure. You must call mte_supp_enc_free() when you are done with the
   encoder. */
MTE_SHARED
MTE_HANDLE mte_supp_enc_alloc(mte_drbgs drbg,
                              uint32_t tok_bytes,
                              mte_verifiers verifiers);

/* Save the encoder state. Returns the saved state and sets *bytes to the length
   of the saved state or NULL on failure. You must call mte_supp_buff_free()
   when you are done with the saved state. */
MTE_SHARED
void *mte_supp_enc_state_save(MTE_CHANDLE encoder, uint32_t *bytes);
MTE_SHARED
char *mte_supp_enc_state_save_b64(MTE_CHANDLE encoder, uint32_t *bytes);

/* Encode the given data of the given byte length in raw form. Returns the
   encoded version on success or NULL on failure. Sets *encoded_bytes to the
   encoded version length in bytes. Sets *status to the status. The encoded
   version is valid only if *status is mte_status_success. You must call
   mte_supp_buff_free() when you are done with the encoded version.

   The timestamp callback and context are used to obtain the timestamp if the
   timestamp verifier is enabled. */
MTE_SHARED
void *mte_supp_enc_encode(MTE_HANDLE encoder,
                          mte_verifier_get_timestamp64 t_cb,
                          void *t_cb_context,
                          const void *data,
                          uint32_t data_bytes,
                          uint32_t *encoded_bytes,
                          mte_status *status);

/* Encode the given data of the given byte length in Base64 form. Returns the
   encoded version on success or NULL on failure. Sets *encoded_bytes to the
   encoded version length in bytes. Sets *status to the status. The encoded
   version is valid only if *status is mte_status_success. You must call
   mte_supp_buff_free() when you are done with the encoded version.

   The timestamp callback and context are used to obtain the timestamp if the
   timestamp verifier is enabled. */
MTE_SHARED
char *mte_supp_enc_encode_b64(MTE_HANDLE encoder,
                              mte_verifier_get_timestamp64 t_cb,
                              void *t_cb_context,
                              const void *data,
                              uint32_t data_bytes,
                              uint32_t *encoded_bytes,
                              mte_status *status);

/* Free an encoder allocated with mte_supp_enc_alloc(). The state of the
   encoder is first zeroed for security. Returns the status. */
MTE_SHARED
mte_status mte_supp_enc_free(MTE_HANDLE encoder);

/* Create a decoder given the DRBG algorithm, token size in bytes, verifiers
   algorithm, timestamp window, and sequence window. Returns a handle to the
   decoder on success or NULL on failure. You must call mte_supp_dec_free()
   when you are done with the decoder. */
MTE_SHARED
MTE_HANDLE mte_supp_dec_alloc(mte_drbgs drbg,
                              uint32_t tok_bytes,
                              mte_verifiers verifiers,
                              uint64_t t_window,
                              int32_t s_window);

/* Save the decoder state. Returns the saved state and sets *bytes to the length
   of the saved state or NULL on failure. You must call mte_supp_buff_free()
   when you are done with the saved state. */
MTE_SHARED
void *mte_supp_dec_state_save(MTE_CHANDLE decoder, uint32_t *bytes);
MTE_SHARED
char *mte_supp_dec_state_save_b64(MTE_CHANDLE decoder, uint32_t *bytes);

/* Decode the given raw encoded data of the given byte length. Returns the
   decoded version on success or NULL on failure. Sets *decoded_bytes to the
   decoded version length in bytes. Sets *status to the status. The decoded
   version is valid only if !mte_base_status_is_error(*status). You must call
   mte_supp_buff_free() when you are done with the decoded version.

   The timestamp callback and context are used to obtain the timestamp if the
   timestamp verifier is enabled. */
MTE_SHARED
void *mte_supp_dec_decode(MTE_HANDLE decoder,
                          mte_verifier_get_timestamp64 t_cb,
                          void *t_cb_context,
                          const void *encoded,
                          uint32_t encoded_bytes,
                          uint32_t *decoded_bytes,
                          mte_status *status);

/* Decode the given Base64-encoded encoded data of the given byte length.
   Returns the decoded version on success or NULL on failure. Sets
   *decoded_bytes to the decoded version length in bytes. Sets *status to the
   status. The decoded version is valid only if
   !mte_base_status_is_error(*status). You must call mte_supp_buff_free() when
   you are done with the decoded version.

   The timestamp callback and context are used to obtain the timestamp if the
   timestamp verifier is enabled. */
MTE_SHARED
void *mte_supp_dec_decode_b64(MTE_HANDLE decoder,
                              mte_verifier_get_timestamp64 t_cb,
                              void *t_cb_context,
                              const void *encoded,
                              uint32_t encoded_bytes,
                              uint32_t *decoded_bytes,
                              mte_status *status);

/* Free a decoder allocated with mte_supp_dec_alloc(). The state of the
   decoder is first zeroed for security. Returns the status. */
MTE_SHARED
mte_status mte_supp_dec_free(MTE_HANDLE decoder);

/* Destroy a buffer. */
MTE_SHARED
void mte_supp_buff_free(void *buff);

#ifdef __cplusplus
}
#endif

#endif


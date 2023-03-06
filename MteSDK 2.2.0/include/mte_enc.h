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
#ifndef mte_enc_h
#define mte_enc_h

#ifndef mte_base_h
#include "mte_base.h"
#endif

/* This is a message encoder.

   To use with a Windows DLL, compile with MTE_BUILD_SHARED defined.

   Notes:
   1. All allocations can be static or dynamic. If dynamic, it is up to the
      caller to free it when done. This library does not allocate or deallocate
      any memory.
   2. A buffer must stay in scope while the call refers to it.
   3. All buffers are reusable and need only be allocated once.

   To create an encoder:
   1. Allocate the encoder state buffer of length:
      a. mte_enc_state_bytes() [provided DRBG]
      b. mte_enc_state_bytes_d() [external DRBG]
   2. Initialize the encoder state with:
      a. mte_enc_state_init() [provided DRBG]
      b. mte_enc_state_init_d() [external DRBG]
   3. Instantiate the encoder with mte_enc_instantiate().

   To save/restore an encoder:
   1. Allocate a buffer of length:
      a. mte_enc_save_bytes() [raw]
      b. mte_enc_save_bytes_b64() [Base64-encoded]
      to hold the saved state.
   2. Save the state with:
      a. mte_enc_state_save() [raw]
      b. mte_enc_state_save_b64() [Base64-encoded]
   3. Restore the state with:
      a. mte_enc_state_restore() [raw]
      b. mte_enc_state_restore_b64() [Base64-encoded]

   To use an encoder:
   1. Allocate the encode buffer of at least length:
      a. mte_enc_buff_bytes() [raw]
      b. mte_enc_buff_bytes_b64() [Base64-encoded]
      where data_bytes is the byte length of the data to encode.
   2. Encode each message with:
      a. mte_enc_encode() [raw]
      b. mte_enc_encode_b64() [Base64-encoded]
      where encoded_bytes will be set to the encoded length. Exactly this length
      must be given to the decoder to decode successfully.

   To destroy an encoder:
   1. Call mte_enc_uninstantiate(). This will zero the state of the encoder for
      security. The encoder must either be instantiated again or restored to
      be usable.
*/
#ifdef __cplusplus
extern "C"
{
#endif

/* Returns the encoder state size for the given DRBG algorithm, token size in
   bytes, and verifiers algorithm. Returns 0 if the combination is not usable.
   The suffixed version of this function to choose must match the suffixed
   version of the state init function that will be used. */
MTE_SHARED MTE_WASM_EXPORT
uint32_t mte_enc_state_bytes(mte_drbgs drbg,
                             uint32_t tok_bytes,
                             mte_verifiers verifiers);
MTE_SHARED MTE_WASM_EXPORT
uint32_t mte_enc_state_bytes_d(uint32_t tok_bytes, mte_verifiers verifiers);

/* Initialize the encoder state given the DRBG algorithm, token size in bytes,
   and verifiers algorithm. Returns the status.

   The state buffer must be of sufficient length to hold the encoder state. See
   mte_enc_state_bytes(). */
MTE_SHARED MTE_WASM_EXPORT
mte_status mte_enc_state_init(MTE_HANDLE state,
                              mte_drbgs drbg,
                              uint32_t tok_bytes,
                              mte_verifiers verifiers);

/* Initialize the encoder state given the DRBG callbacks, DRBG state pointer,
   token size in bytes, and verifiers algorithm. Returns the status.

   The state buffer must be of sufficient length to hold the encoder state. See
   mte_enc_state_bytes_d().

   The rc_cb argument can be NULL if reseed information will not be requested.
   The ssb_cb, ss_cb, and sr_cb arguments can be NULL if state save/restore
   will not be used.

   The drbg_state must point at the external DRBG state and must remain in scope
   as long as the state will be used. */
MTE_SHARED MTE_WASM_EXPORT
mte_status mte_enc_state_init_d(MTE_HANDLE state,
                                mte_drbg_instantiate i_cb,
                                mte_drbg_reseed_counter rc_cb,
                                mte_drbg_state_save_bytes ssb_cb,
                                mte_drbg_state_save ss_cb,
                                mte_drbg_state_restore sr_cb,
                                mte_drbg_generate g_cb,
                                mte_drbg_uninstantiate u_cb,
                                void *drbg_state,
                                uint32_t tok_bytes,
                                mte_verifiers verifiers);

/* Instantiate the encoder given the entropy input callback/context, nonce
   callback/context, personalization string, and length of the personalization
   string in bytes. Returns the status. */
MTE_SHARED
mte_status mte_enc_instantiate(MTE_HANDLE state,
                               mte_drbg_get_entropy_input ei_cb,
                               void *ei_cb_context,
                               mte_drbg_get_nonce n_cb,
                               void *n_cb_context,
                               const void *ps, uint32_t ps_bytes);

/* Returns the reseed counter. */
MTE_SHARED
uint64_t mte_enc_reseed_counter(MTE_CHANDLE state);

/* Returns the state save size [raw]. Returns 0 if save is unsupported. */
MTE_SHARED MTE_WASM_EXPORT
uint32_t mte_enc_save_bytes(MTE_CHANDLE state);

/* Returns the state save size [Base64-encoded]. Returns 0 if save is
   unsupported. */
MTE_SHARED MTE_WASM_EXPORT
uint32_t mte_enc_save_bytes_b64(MTE_CHANDLE state);

/* Save the encoder state to the given buffer in raw form. The size of the
   buffer must be mte_enc_save_bytes() and that is the length of the raw saved
   state. Returns mte_status_unsupported if not supported; otherwise returns
   mte_status_success. */
MTE_SHARED MTE_WASM_EXPORT
mte_status mte_enc_state_save(MTE_CHANDLE state, void *saved);

/* Save the encoder state to the given buffer encoded in Base64. The size of the
   buffer must be mte_enc_save_bytes_b64() and the result is null-terminated.
   Returns mte_status_unsupported if not supported; otherwise returns
   mte_status_success. */
MTE_SHARED MTE_WASM_EXPORT
mte_status mte_enc_state_save_b64(MTE_CHANDLE state, void *saved);

/* Restore the encoder state from the given buffer in raw form. Returns
   mte_status_unsupported if not supported; otherwise returns
   mte_status_success. */
MTE_SHARED MTE_WASM_EXPORT
mte_status mte_enc_state_restore(MTE_HANDLE state, const void *saved);

/* Restore the encoder state from the given buffer in raw form. Returns
   mte_status_unsupported if not supported; otherwise returns
   mte_status_success. */
MTE_SHARED MTE_WASM_EXPORT
mte_status mte_enc_state_restore_b64(MTE_HANDLE state, const void *saved);

/* Returns the encode buffer size [raw] in bytes given the data length in bytes.
   The encode buffer provided to mte_enc_encode() must be of at least this
   length. */
MTE_SHARED MTE_WASM_EXPORT
uint32_t mte_enc_buff_bytes(MTE_CHANDLE state, uint32_t data_bytes);

/* Returns the encode buffer size [Base64-encoded] in bytes given the token
   size in bytes, verifiers algorithm, and data length in bytes. The encode
   buffer provided to mte_enc_encode_b64() must be of at least this length. */
MTE_SHARED MTE_WASM_EXPORT
uint32_t mte_enc_buff_bytes_b64(MTE_CHANDLE state, uint32_t data_bytes);

/* Encode the given data of the given byte length to the given encode buffer in
   raw form. Returns the status. Sets *encoded_off to the offset in the encoded
   buffer where the encoded version can be found and sets *encoded_bytes to the
   raw encoded version length in bytes. The encoded version is valid only if
   mte_status_success is returned.

   The timestamp callback and context are used to obtain the timestamp if the
   timestamp verifier is enabled.

   The encoded buffer must be of sufficient length to hold the encoded version.
   See mte_enc_buff_bytes(). */
MTE_SHARED
mte_status mte_enc_encode(MTE_HANDLE state,
                          mte_verifier_get_timestamp64 t_cb, void *t_cb_context,
                          const void *data, uint32_t data_bytes,
                          void *encoded,
                          uint32_t *encoded_off,
                          uint32_t *encoded_bytes);

/* Encode the given data of the given byte length to the given encode buffer,
   encoded in Base64. Returns the status. Sets *encoded_off to the offset in
   the encoded buffer where the Base64 version can be found and sets
   *encoded_bytes to the Base64-encoded version length in bytes. The encoded
   version is null terminated, but *encoded_bytes excludes the null terminator.
   The encoded version is valid only if mte_status_success is returned.

   The timestamp callback and context are used to obtain the timestamp if the
   timestamp verifier is enabled.

   The encoded buffer must be of sufficient length to hold the encoded version.
   See mte_enc_buff_bytes_b64(). */
MTE_SHARED
mte_status mte_enc_encode_b64(MTE_HANDLE state,
                              mte_verifier_get_timestamp64 t_cb,
                              void *t_cb_context,
                              const void *data,
                              uint32_t data_bytes,
                              void *encoded,
                              uint32_t *encoded_off,
                              uint32_t *encoded_bytes);

/* Uninstantiate the encoder. Returns the status. */
MTE_SHARED MTE_WASM_EXPORT
mte_status mte_enc_uninstantiate(MTE_HANDLE state);

#ifdef __cplusplus
}
#endif

#endif


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
#ifndef mte_dec_h
#define mte_dec_h

#ifndef mte_base_h
#include "mte_base.h"
#endif

/* This is a message decoder.

   To use with a Windows DLL, compile with MTE_BUILD_SHARED defined.

   Notes:
   1. All allocations can be static or dynamic. If dynamic, it is up to the
      caller to free it when done. This library does not allocate or deallocate
      any memory.
   2. A buffer must stay in scope while the call refers to it.
   3. All buffers are reusable and need only be allocated once.

   To create a decoder:
   1. Allocate the decoder state buffer of length:
      a. mte_dec_state_bytes() [provided DRBG]
      b. mte_dec_state_bytes_d() [external DRBG]
   2. Initialize the decoder state with:
      a. mte_dec_state_init() [provided DRBG]
      b. mte_dec_state_init_d() [external DRBG]
   3. Instantiate the decoder with mte_dec_instantiate().

   To save/restore a decoder:
   1. Allocate a buffer of length:
      a. mte_dec_save_bytes() [raw]
      b. mte_dec_save_bytes_b64() [Base64-encoded]
      to hold the saved state.
   2. Save the state with:
      a. mte_dec_state_save() [raw]
      b. mte_dec_state_save_b64() [Base64-encoded]
   3. Restore the state with:
      a. mte_dec_state_restore() [raw]
      b. mte_dec_state_restore_b64() [Base64-encoded]

   To use a decoder:
   1. Allocate the decode buffer of at least length:
      a. mte_dec_buff_bytes() [raw]
      b. mte_dec_buff_bytes_b64() [Base64-encoded]
      where encoded_bytes is the byte length of the encoded data.
   2. Decode each message with:
      a. mte_dec_decode() [raw]
      b. mte_dec_decode_b64() [Base64-encoded]
      where decoded_bytes will be set to the decoded length.
   3. The encode timestamp is retrieved with mte_dec_enc_ts().
   4. The decode timestamp is retrieved with mte_dec_dec_ts().
   5. The number of messages skipped is retrieved with mte_dec_msg_skipped().

   To destroy a decoder:
   1. Call mte_dec_uninstantiate(). This will zero the state of the decoder for
      security. The decoder must either be instantiated again or restored to
      be usable.
*/
#ifdef __cplusplus
extern "C"
{
#endif

/* Returns the decoder state size for the given DRBG algorithm, token size in
   bytes, and verifiers algorithm. Returns 0 if the combination is not usable.
   The suffixed version of this function to choose must match the suffixed
   version of the state init function that will be used. */
MTE_SHARED MTE_WASM_EXPORT
uint32_t mte_dec_state_bytes(mte_drbgs drbg,
                             uint32_t tok_bytes,
                             mte_verifiers verifiers);
MTE_SHARED MTE_WASM_EXPORT
uint32_t mte_dec_state_bytes_d(uint32_t tok_bytes, mte_verifiers verifiers);

/* Initialize the decoder state given the DRBG algorithm, token size in bytes,
   verifiers algorithm, timestamp window, and sequence window. Returns the
   status.

   If a sequencing verifier is used, s_window has the following properties:
     a. If s_window == 0, any message out of sequence is flagged as an error
        before attempting decode.
     b. If -63 <= s_window <= -1, any message that comes out of sequence within
        abs(s_window) messages will be decoded, but the state is not advanced,
        so an earlier message can be decoded later. If a message comes out of
        sequence more than abs(s_window) ahead but no more than 2*abs(s_window)
        ahead, the message will be decoded and the state is advanced so the
        sequence number received is now only abs(s_window) ahead; any messages
        that come in before the base sequence number are flagged as an error
        before attempting to decode.
     c. If s_window > 0, any message that comes out of sequence within s_window
        messages will be decoded and the state is advanced so the sequence
        number received is now the base sequence number; any messages that come
        in before the new base sequence number are flagged as an error before
        attempting to decode.

   The state buffer must be of sufficient length to hold the decoder state. See
   mte_dec_state_bytes(). */
MTE_SHARED
mte_status mte_dec_state_init(MTE_HANDLE state,
                              mte_drbgs drbg,
                              uint32_t tok_bytes,
                              mte_verifiers verifiers,
                              uint64_t t_window,
                              int32_t s_window);

/* Initialize the decoder state given the DRBG callbacks, DRBG state pointer,
   token size in bytes, verifiers algorithm, timestamp window, and sequence
   window. Returns the status.

   If a sequencing verifier is used, s_window has the following properties:
     a. If s_window == 0, any message out of sequence is flagged as an error
        before attempting decode.
     b. If -63 <= s_window <= -1, any message that comes out of sequence within
        abs(s_window) messages will be decoded, but the state is not advanced,
        so an earlier message can be decoded later. If a message comes out of
        sequence more than abs(s_window) ahead but no more than 2*abs(s_window)
        ahead, the message will be decoded and the state is advanced so the
        sequence number received is now only abs(s_window) ahead; any messages
        that come in before the base sequence number are flagged as an error
        before attempting to decode.
     c. If s_window > 0, any message that comes out of sequence within s_window
        messages will be decoded and the state is advanced so the sequence
        number received is now the base sequence number; any messages that come
        in before the new base sequence number are flagged as an error before
        attempting to decode.

   The state buffer must be of sufficient length to hold the decoder state. See
   mte_dec_state_bytes_d().

   The rc_cb argument can be NULL if reseed information will not be requested.
   The ssb_cb, ss_cb, and sr_cb arguments can be NULL if state save/restore
   will not be used.

   The drbg_state must point at the external DRBG state and must remain in scope
   as long as the state will be used. */
MTE_SHARED
mte_status mte_dec_state_init_d(MTE_HANDLE state,
                                mte_drbg_instantiate i_cb,
                                mte_drbg_reseed_counter rc_cb,
                                mte_drbg_state_save_bytes ssb_cb,
                                mte_drbg_state_save ss_cb,
                                mte_drbg_state_restore sr_cb,
                                mte_drbg_generate g_cb,
                                mte_drbg_uninstantiate u_cb,
                                void *drbg_state,
                                uint32_t tok_bytes,
                                mte_verifiers verifiers,
                                uint64_t t_window,
                                int32_t s_window);

/* Instantiate the decoder given the entropy input callback/context, nonce
   callback/context, personalization string, and length of the personalization
   string in bytes. Returns the status. */
MTE_SHARED
mte_status mte_dec_instantiate(MTE_HANDLE state,
                               mte_drbg_get_entropy_input ei_cb,
                               void *ei_cb_context,
                               mte_drbg_get_nonce n_cb, void *n_cb_context,
                               const void *ps, uint32_t ps_bytes);

/* Returns the reseed counter. */
MTE_SHARED
uint64_t mte_dec_reseed_counter(MTE_CHANDLE state);

/* Returns the state save size [raw]. Returns 0 if save is unsupported. */
MTE_SHARED MTE_WASM_EXPORT
uint32_t mte_dec_save_bytes(MTE_CHANDLE state);

/* Returns the state save size [Base64-encoded]. Returns 0 if save is
   unsupported. */
MTE_SHARED MTE_WASM_EXPORT
uint32_t mte_dec_save_bytes_b64(MTE_CHANDLE state);

/* Save the decoder state to the given buffer in raw form. The size of the
   buffer must be mte_dec_save_bytes() and that is the length of the raw saved
   state. Returns mte_status_unsupported if not supported; otherwise returns
   mte_status_success. */
MTE_SHARED MTE_WASM_EXPORT
mte_status mte_dec_state_save(MTE_CHANDLE state, void *saved);

/* Save the decoder state to the given buffer encoded in Base64. The size of the
   buffer must be mte_dec_save_bytes_b64() and the result is null-terminated.
   Returns mte_status_unsupported if not supported; otherwise returns
   mte_status_success. */
MTE_SHARED MTE_WASM_EXPORT
mte_status mte_dec_state_save_b64(MTE_CHANDLE state, void *saved);

/* Restore the decoder state from the given buffer in raw form. Returns
   mte_status_unsupported if not supported; otherwise returns
   mte_status_success. */
MTE_SHARED MTE_WASM_EXPORT
mte_status mte_dec_state_restore(MTE_HANDLE state, const void *saved);

/* Restore the decoder state from the given buffer in raw form. Returns
   mte_status_unsupported if not supported; otherwise returns
   mte_status_success. */
MTE_SHARED MTE_WASM_EXPORT
mte_status mte_dec_state_restore_b64(MTE_HANDLE state, const void *saved);

/* Returns the decode buffer size [raw] in bytes given the encoded length in
   bytes. The decode buffer provided to mte_dec_decode() must be of at least
   this length. */
MTE_SHARED MTE_WASM_EXPORT
uint32_t mte_dec_buff_bytes(MTE_CHANDLE state, uint32_t encoded_bytes);

/* Returns the decode buffer size [Base64-encoded] in bytes given the encoded
   length in bytes. The decode buffer provided to mte_dec_decode_b64() must be
   of at least this length. */
MTE_SHARED MTE_WASM_EXPORT
uint32_t mte_dec_buff_bytes_b64(MTE_CHANDLE state, uint32_t encoded_bytes);

/* Decode the given raw encoded data to the given decode buffer. Returns the
   status. Sets *decoded_off to the offset in the decoded buffer where the
   decoded version can be found and sets *decoded_bytes to the decoded data
   length in bytes. The decoded version is valid only if
   !mte_base_status_is_error(status). A null terminator is appended to the
   decoded data, but is not included in *decoded_bytes.

   The timestamp callback and context are used to obtain the timestamp if the
   timestamp verifier is enabled.

   The decoded buffer must be of sufficient length to hold the decoded version.
   See mte_dec_buff_bytes(). */
MTE_SHARED
mte_status mte_dec_decode(MTE_HANDLE state,
                          mte_verifier_get_timestamp64 t_cb, void *t_cb_context,
                          const void *encoded, uint32_t encoded_bytes,
                          void *decoded,
                          uint32_t *decoded_off,
                          uint32_t *decoded_bytes);

/* Decode the given Base64-encoded encoded data to the given decode buffer.
   Returns the status. Sets *decoded_off to the offset in the decoded buffer
   where the decoded version can be found and sets *decoded_bytes to the decoded
   data length in bytes. The decoded version is valid only if
   !mte_base_status_is_error(status). A null terminator is appended to the
   decoded data, but is not included in *decoded_bytes.

   The timestamp callback and context are used to obtain the timestamp if the
   timestamp verifier is enabled.

   The decoded buffer must be of sufficient length to hold the decoded version.
   See mte_dec_buff_bytes_b64(). */
MTE_SHARED
mte_status mte_dec_decode_b64(MTE_HANDLE state,
                              mte_verifier_get_timestamp64 t_cb,
                              void *t_cb_context,
                              const void *encoded,
                              uint32_t encoded_bytes,
                              void *decoded,
                              uint32_t *decoded_off,
                              uint32_t *decoded_bytes);

/* Returns the encode/decode timestamp from the most recent decode. */
MTE_SHARED
uint64_t mte_dec_enc_ts(MTE_CHANDLE state);
MTE_SHARED
uint64_t mte_dec_dec_ts(MTE_CHANDLE state);

/* If the sequence window is non-negative, returns the messages skipped from the
   most recent decode; otherwise it returns the number of messages ahead of the
   base sequence from the most recent decode. */
MTE_SHARED MTE_WASM_EXPORT
uint32_t mte_dec_msg_skipped(MTE_CHANDLE state);

/* Uninstantiate the decoder. Returns the status. */
MTE_SHARED MTE_WASM_EXPORT
mte_status mte_dec_uninstantiate(MTE_HANDLE state);

#ifdef __cplusplus
}
#endif

#endif


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
#ifndef mte_mke_dec_h
#define mte_mke_dec_h

#ifndef mte_base_h
#include "mte_base.h"
#endif
#ifndef mte_cipher_defs_h
#include "mte_cipher_defs.h"
#endif
#ifndef mte_ciphers_h
#include "mte_ciphers.h"
#endif
#ifndef mte_hash_defs_h
#include "mte_hash_defs.h"
#endif
#ifndef mte_hashes_h
#include "mte_hashes.h"
#endif

/* This is the Managed-Key Encryption message decoder.

   To use with a Windows DLL, compile with MTE_BUILD_SHARED defined.

   Notes:
   1. All allocations can be static or dynamic. If dynamic, it is up to the
      caller to free it when done. This library does not allocate or deallocate
      any memory.
   2. A buffer must stay in scope while the call refers to it.
   3. All buffers are reusable and need only be allocated once.

   To create a decoder:
   1. Allocate the decoder state buffer of length:
      a. mte_mke_dec_state_bytes() [provided DRBG, cipher, and hash]
      b. mte_mke_dec_state_bytes_d() [external DRBG, provided cipher and hash]
      c. mte_mke_dec_state_bytes_c() [external cipher, provided DRBG and hash]
      d. mte_mke_dec_state_bytes_h() [external hash, provided DRBG and cipher]
      e. mte_mke_dec_state_bytes_dc() [external DRBG and cipher, provided hash]
      f. mte_mke_dec_state_bytes_dh() [external DRBG and hash, provided cipher]
      g. mte_mke_dec_state_bytes_ch() [external cipher and hash, provided DRBG]
      h. mte_mke_dec_state_bytes_dch() [external DRBG, cipher, and hash]
   2. Initialize the decoder state with:
      a. mte_mke_dec_state_init() [provided DRBG, cipher, and hash]
      b. mte_mke_dec_state_init_d() [external DRBG, provided cipher and hash]
      c. mte_mke_dec_state_init_c() [external cipher, provided DRBG and hash]
      d. mte_mke_dec_state_init_h() [external hash, provided DRBG and cipher]
      e. mte_mke_dec_state_init_dc() [external DRBG and cipher, provided hash]
      f. mte_mke_dec_state_init_dh() [external DRBG and hash, provided cipher]
      g. mte_mke_dec_state_init_ch() [external cipher and hash, provided DRBG]
      h. mte_mke_dec_state_init_dch() [external DRBG, cipher, and hash]
   3. Instantiate the decoder with mte_mke_dec_instantiate().

   To save/restore a decoder:
   1. Allocate a buffer of length:
      a. mte_mke_dec_save_bytes() [raw]
      b. mte_mke_dec_save_bytes_b64() [Base64-encoded]
      to hold the saved state.
   2. Save the state with:
      a. mte_mke_dec_state_save() [raw]
      b. mte_mke_dec_state_save_b64() [Base64-encoded]
   3. Restore the state with:
      a. mte_mke_dec_state_restore() [raw]
      b. mte_mke_dec_state_restore_b64() [Base64-encoded]

   To use a decoder:
   1. Allocate the decode buffer of at least length:
      a. mte_mke_dec_buff_bytes() [raw]
      b. mte_mke_dec_buff_bytes_b64() [Base64-encoded]
      where encoded_bytes is the byte length of the encoded data.
   2. Decode each message with:
      a. mte_mke_dec_decode() [raw]
      b. mte_mke_dec_decode_b64() [Base64-encoded]
      where decoded_bytes will be set to the decoded length.
   3. The encode timestamp is retrieved with mte_mke_dec_enc_ts().
   4. The decode timestamp is retrieved with mte_mke_dec_dec_ts().
   5. The number of messages skipped is retrieved with
      mte_mke_dec_msg_skipped().

   To use as a chunk-based decryptor:
   1. Allocate the chunk-based decryption state of at least length
      mte_mke_dec_decrypt_state_bytes().
   2. Call mte_mke_dec_decrypt_start() to start the chunk-based session.
   3. Call mte_mke_dec_decrypt_chunk() repeatedly to decrypt each chunk of data.
   4. Call mte_mke_dec_decrypt_finish().
   The results from step 3-4, concatenated in order, form the full result. Only
   chunk-encrypted data can be decrypted since this is intended for large
   data. The sequencing verifier is not supported for chunk-based decryption.

   To destroy a decoder:
   1. Call mte_mke_dec_uninstantiate(). This will zero the state of the decoder
      for security. The decoder must either be instantiated again or restored to
      be usable.
*/
#ifdef __cplusplus
extern "C"
{
#endif

/* Returns the decoder state size for the given DRBG algorithm, token size in
   bytes, verifiers algorithm, and cipher/hash algorithms. Returns 0 if the
   combination is not usable. The suffixed version of this function to choose
   must match the suffixed version of the state init function that will be
   used. */
MTE_SHARED MTE_WASM_EXPORT
uint32_t mte_mke_dec_state_bytes(mte_drbgs drbg,
                                 uint32_t tok_bytes,
                                 mte_verifiers verifiers,
                                 mte_ciphers cipher,
                                 mte_hashes hash);
MTE_SHARED MTE_WASM_EXPORT
uint32_t mte_mke_dec_state_bytes_d(uint32_t tok_bytes,
                                   mte_verifiers verifiers,
                                   mte_ciphers cipher,
                                   mte_hashes hash);
MTE_SHARED MTE_WASM_EXPORT
uint32_t mte_mke_dec_state_bytes_c(mte_drbgs drbg,
                                   uint32_t tok_bytes,
                                   mte_verifiers verifiers,
                                   mte_hashes hash);
MTE_SHARED MTE_WASM_EXPORT
uint32_t mte_mke_dec_state_bytes_h(mte_drbgs drbg,
                                   uint32_t tok_bytes,
                                   mte_verifiers verifiers,
                                   mte_ciphers cipher);
MTE_SHARED MTE_WASM_EXPORT
uint32_t mte_mke_dec_state_bytes_dc(uint32_t tok_bytes,
                                    mte_verifiers verifiers,
                                    mte_hashes hash);
MTE_SHARED MTE_WASM_EXPORT
uint32_t mte_mke_dec_state_bytes_dh(uint32_t tok_bytes,
                                    mte_verifiers verifiers,
                                    mte_ciphers cipher);
MTE_SHARED MTE_WASM_EXPORT
uint32_t mte_mke_dec_state_bytes_ch(mte_drbgs drbg,
                                    uint32_t tok_bytes,
                                    mte_verifiers verifiers);
MTE_SHARED MTE_WASM_EXPORT
uint32_t mte_mke_dec_state_bytes_dch(uint32_t tok_bytes,
                                     mte_verifiers verifiers);

/* Initialize the decoder state given the DRBG algorithm, token size in bytes,
   verifiers algorithm, cipher/hash algorithms, timestamp window, and sequence
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
   mte_mke_dec_state_bytes(). */
MTE_SHARED
mte_status mte_mke_dec_state_init(MTE_HANDLE state,
                                  mte_drbgs drbg,
                                  uint32_t tok_bytes,
                                  mte_verifiers verifiers,
                                  mte_ciphers cipher,
                                  mte_hashes hash,
                                  uint64_t t_window,
                                  int32_t s_window);

/* Initialize the decoder state given the DRBG callbacks, DRBG state pointer,
   token size in bytes, verifiers algorithm, cipher algorithm, hash algorithm,
   timestamp window, and sequence window. Returns the status.

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
   mte_mke_dec_state_bytes_d().

   The rc_cb argument can be NULL if reseed information will not be requested.
   The ssb_cb, ss_cb, and sr_cb arguments can be NULL if state save/restore
   will not be used.

   The drbg_state must point at the external DRBG state and must remain in scope
   as long as the state will be used. */
MTE_SHARED
mte_status mte_mke_dec_state_init_d(MTE_HANDLE state,
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
                                    mte_ciphers cipher,
                                    mte_hashes hash,
                                    uint64_t t_window,
                                    int32_t s_window);

/* Initialize the decoder state given the DRBG algorithm, token size in bytes,
   verifiers algorithm, cipher callbacks, cipher key/block size, cipher state
   pointer, hash algorithm, timestamp window, and sequence window. Returns the
   status.

   The block_bytes cannot exceed 128 bytes.

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
   mte_mke_dec_state_bytes_c().

   The cipher_state must point at the external cipher state and must remain in
   scope as long as the state will be used. */
MTE_SHARED
mte_status mte_mke_dec_state_init_c(MTE_HANDLE state,
                                    mte_drbgs drbg,
                                    uint32_t tok_bytes,
                                    mte_verifiers verifiers,
                                    mte_cipher_key cdk_cb,
                                    mte_cipher_enc_dec cd_cb,
                                    mte_cipher_uninit cu_cb,
                                    uint32_t key_bytes,
                                    uint32_t block_bytes,
                                    void *cipher_state,
                                    mte_hashes hash,
                                    uint64_t t_window,
                                    int32_t s_window);

/* Initialize the decoder state given the DRBG algorithm, token size in bytes,
   verifiers algorithm, cipher algorithm, hash callbacks, hash digest size, hash
   state pointer, timestamp window, and sequence window. Returns the status.

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
   mte_mke_dec_state_bytes_h().

   The hash_state must point at the external hash state and must remain in scope
   as long as the state will be used. */
MTE_SHARED
mte_status mte_mke_dec_state_init_h(MTE_HANDLE state,
                                    mte_drbgs drbg,
                                    uint32_t tok_bytes,
                                    mte_verifiers verifiers,
                                    mte_ciphers cipher,
                                    mte_hash_calc hc_cb,
                                    mte_hash_start hs_cb,
                                    mte_hash_feed hf_cb,
                                    mte_hash_finish hfin_cb,
                                    uint32_t digest_bytes,
                                    void *hash_state,
                                    uint64_t t_window,
                                    int32_t s_window);

/* Initialize the decoder state given the DRBG callbacks, DRBG state pointer,
   token size in bytes, verifiers algorithm, cipher callbacks, cipher key/block
   size, cipher state pointer, hash algorithm, timestamp window, and sequence
   window. Returns the status.

   The block_bytes cannot exceed 128 bytes.

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
   mte_mke_dec_state_bytes_dc().

   The rc_cb argument can be NULL if reseed information will not be requested.
   The ssb_cb, ss_cb, and sr_cb arguments can be NULL if state save/restore
   will not be used.

   The drbg_state must point at the external DRBG state and must remain in scope
   as long as the state will be used.

   The cipher_state must point at the external cipher state and must remain in
   scope as long as the state will be used. */
MTE_SHARED
mte_status mte_mke_dec_state_init_dc(MTE_HANDLE state,
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
                                     mte_cipher_key cdk_cb,
                                     mte_cipher_enc_dec cd_cb,
                                     mte_cipher_uninit cu_cb,
                                     uint32_t key_bytes,
                                     uint32_t block_bytes,
                                     void *cipher_state,
                                     mte_hashes hash,
                                     uint64_t t_window,
                                     int32_t s_window);

/* Initialize the decoder state given the DRBG callbacks, DRBG state pointer,
   token size in bytes, verifiers algorithm, cipher algorithm, hash callbacks,
   hash digest size, hash state pointer, timestamp window, and sequence window.
   Returns the status.

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
   mte_mke_dec_state_bytes_dh().

   The rc_cb argument can be NULL if reseed information will not be requested.
   The ssb_cb, ss_cb, and sr_cb arguments can be NULL if state save/restore
   will not be used.

   The drbg_state must point at the external DRBG state and must remain in scope
   as long as the state will be used.

   The hash_state must point at the external hash state and must remain in scope
   as long as the state will be used. */
MTE_SHARED
mte_status mte_mke_dec_state_init_dh(MTE_HANDLE state,
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
                                     mte_ciphers cipher,
                                     mte_hash_calc hc_cb,
                                     mte_hash_start hs_cb,
                                     mte_hash_feed hf_cb,
                                     mte_hash_finish hfin_cb,
                                     uint32_t digest_bytes,
                                     void *hash_state,
                                     uint64_t t_window,
                                     int32_t s_window);

/* Initialize the decoder state given the DRBG algorithm, token size in bytes,
   verifiers algorithm, cipher callbacks, cipher key/block size, cipher state
   pointer, hash callbacks, hash digest size, hash state pointer, timestamp
   window, and sequence window. Returns the status.

   The block_bytes cannot exceed 128 bytes.

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
   mte_mke_dec_state_bytes_ch().

   The cipher_state must point at the external cipher state and must remain in
   scope as long as the state will be used.

   The hash_state must point at the external hash state and must remain in scope
   as long as the state will be used. */
MTE_SHARED
mte_status mte_mke_dec_state_init_ch(MTE_HANDLE state,
                                     mte_drbgs drbg,
                                     uint32_t tok_bytes,
                                     mte_verifiers verifiers,
                                     mte_cipher_key cdk_cb,
                                     mte_cipher_enc_dec cd_cb,
                                     mte_cipher_uninit cu_cb,
                                     uint32_t key_bytes,
                                     uint32_t block_bytes,
                                     void *cipher_state,
                                     mte_hash_calc hc_cb,
                                     mte_hash_start hs_cb,
                                     mte_hash_feed hf_cb,
                                     mte_hash_finish hfin_cb,
                                     uint32_t digest_bytes,
                                     void *hash_state,
                                     uint64_t t_window,
                                     int32_t s_window);

/* Initialize the decoder state given the DRBG callbacks, DRBG state pointer,
   token size in bytes, verifiers algorithm, cipher callbacks, cipher key/block
   size, cipher state pointer, hash callbacks, hash digest size, hash state
   pointer, timestamp window, and sequence window. Returns the status.

   The block_bytes cannot exceed 128 bytes.

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
   mte_mke_dec_state_bytes_dch().

   The rc_cb argument can be NULL if reseed information will not be requested.
   The ssb_cb, ss_cb, and sr_cb arguments can be NULL if state save/restore
   will not be used.

   The drbg_state must point at the external DRBG state and must remain in scope
   as long as the state will be used.

   The cipher_state must point at the external cipher state and must remain in
   scope as long as the state will be used.

   The hash_state must point at the external hash state and must remain in scope
   as long as the state will be used. */
MTE_SHARED
mte_status mte_mke_dec_state_init_dch(MTE_HANDLE state,
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
                                      mte_cipher_key cdk_cb,
                                      mte_cipher_enc_dec cd_cb,
                                      mte_cipher_uninit cu_cb,
                                      uint32_t key_bytes,
                                      uint32_t block_bytes,
                                      void *cipher_state,
                                      mte_hash_calc hc_cb,
                                      mte_hash_start hs_cb,
                                      mte_hash_feed hf_cb,
                                      mte_hash_finish hfin_cb,
                                      uint32_t digest_bytes,
                                      void *hash_state,
                                      uint64_t t_window,
                                      int32_t s_window);

/* Instantiate the decoder given the entropy input callback/context, nonce
   callback/context, personalization string, and length of the personalization
   string in bytes. Returns the status. */
MTE_SHARED
mte_status mte_mke_dec_instantiate(MTE_HANDLE state,
                                   mte_drbg_get_entropy_input ei_cb,
                                   void *ei_cb_context,
                                   mte_drbg_get_nonce n_cb,
                                   void *n_cb_context,
                                   const void *ps, uint32_t ps_bytes);

/* Returns the reseed counter. */
MTE_SHARED
uint64_t mte_mke_dec_reseed_counter(MTE_CHANDLE state);

/* Returns the state save size [raw]. Returns 0 if save is unsupported. */
MTE_SHARED MTE_WASM_EXPORT
uint32_t mte_mke_dec_save_bytes(MTE_CHANDLE state);

/* Returns the state save size [Base64-encoded]. Returns 0 if save is
   unsupported. */
MTE_SHARED MTE_WASM_EXPORT
uint32_t mte_mke_dec_save_bytes_b64(MTE_CHANDLE state);

/* Save the decoder state to the given buffer in raw form. The size of the
   buffer must be mte_mke_dec_save_bytes() and that is the length of the raw
   saved state. Returns mte_status_unsupported if not supported; otherwise
   returns mte_status_success. */
MTE_SHARED MTE_WASM_EXPORT
mte_status mte_mke_dec_state_save(MTE_CHANDLE state, void *saved);

/* Save the decoder state to the given buffer encoded in Base64. The size of
   the buffer must be mte_mke_dec_save_bytes_b64() and the result is null-
   terminated. Returns mte_status_unsupported if not supported; otherwise
   returns mte_status_success. */
MTE_SHARED MTE_WASM_EXPORT
mte_status mte_mke_dec_state_save_b64(MTE_CHANDLE state, void *saved);

/* Restore the decoder state from the given buffer in raw form. Returns
   mte_status_unsupported if not supported; otherwise returns
   mte_status_success. */
MTE_SHARED MTE_WASM_EXPORT
mte_status mte_mke_dec_state_restore(MTE_HANDLE state, const void *saved);

/* Restore the decoder state from the given buffer in raw form. Returns
   mte_status_unsupported if not supported; otherwise returns
   mte_status_success. */
MTE_SHARED MTE_WASM_EXPORT
mte_status mte_mke_dec_state_restore_b64(MTE_HANDLE state, const void *saved);

/* Returns the decode buffer size [raw] in bytes given the encoded length in
   bytes. Returns 0 if the input is invalid. The decode buffer provided to
   mte_mke_dec_decode() must be of at least this length. */
MTE_SHARED MTE_WASM_EXPORT
uint32_t mte_mke_dec_buff_bytes(MTE_CHANDLE state, uint32_t encoded_bytes);

/* Returns the decode buffer size [Base64-encoded] in bytes given the encoded
   length in bytes. The decode buffer provided to mte_mke_dec_decode_b64() must
   be of at least this length. */
MTE_SHARED MTE_WASM_EXPORT
uint32_t mte_mke_dec_buff_bytes_b64(MTE_CHANDLE state, uint32_t encoded_bytes);

/* Decode the given raw encoded data to the given decode buffer. Returns the
   status. Sets *decoded_off to the offset in the decoded buffer where the
   decoded version can be found and sets *decoded_bytes to the decoded data
   length in bytes. The decoded version is valid only if the status indicates
   success or a non-fatal error. A null terminator is appended to the decoded
   data, but is not included in *decoded_bytes.

   The timestamp callback and context are used to obtain the timestamp if the
   timestamp verifier is enabled.

   The decoded buffer must be of sufficient length to hold the decoded version.
   See mte_mke_dec_buff_bytes(). */
MTE_SHARED
mte_status mte_mke_dec_decode(MTE_HANDLE state,
                              mte_verifier_get_timestamp64 t_cb,
                              void *t_cb_context,
                              const void *encoded, uint32_t encoded_bytes,
                              void *decoded,
                              uint32_t *decoded_off,
                              uint32_t *decoded_bytes);

/* Decode the given Base64-encoded encoded data to the given decode buffer.
   Returns the status. Sets *decoded_off to the offset in the decoded buffer
   where the decoded version can be found and sets *decoded_bytes to the decoded
   data length in bytes. The decoded version is valid only if the status
   indicates success or a non-fatal error. A null terminator is appended to the
   decoded data, but is not included in *decoded_bytes.

   The timestamp callback and context are used to obtain the timestamp if the
   timestamp verifier is enabled.

   The decoded buffer must be of sufficient length to hold the decoded version.
   See mte_mke_dec_buff_bytes_b64(). */
MTE_SHARED
mte_status mte_mke_dec_decode_b64(MTE_HANDLE state,
                                  mte_verifier_get_timestamp64 t_cb,
                                  void *t_cb_context,
                                  const void *encoded,
                                  uint32_t encoded_bytes,
                                  void *decoded,
                                  uint32_t *decoded_off,
                                  uint32_t *decoded_bytes);

/* Returns the chunk-based decryption state size in bytes. The c_state buffer
   provided to the mte_mke_dec_decrypt_*() functions must be of at least this
   length. */
MTE_SHARED MTE_WASM_EXPORT
uint32_t mte_mke_dec_decrypt_state_bytes(MTE_CHANDLE state);

/* Start a chunk-based decryption session. Returns the status. Initializes the
   state to the c_state buffer. This state is used by the other chunk-based
   functions.

   The c_state buffer must be of sufficient length. See
   mte_mke_dec_decrypt_state_bytes(). */
MTE_SHARED MTE_WASM_EXPORT
mte_status mte_mke_dec_decrypt_start(MTE_HANDLE state, MTE_HANDLE c_state);

/* Decrypt a chunk of data in a chunk-based decryption session. The encrypted
   data of length encrypted_bytes is used as input and some decrypted data is
   written to the decrypted buffer and *decrypted_bytes is set to the amount of
   decrypted data written. The amount decrypted may be less than the input size.
   Returns the status.

   The decrypted buffer must be at least encrypted_bytes plus the cipher block
   size bytes in length to hold the decrypted version. The decrypted buffer
   cannot overlap the encrypted buffer. */
MTE_SHARED MTE_WASM_EXPORT
mte_status mte_mke_dec_decrypt_chunk(MTE_HANDLE state, MTE_HANDLE c_state,
                                     const void *encrypted,
                                     uint32_t encrypted_bytes,
                                     void *decrypted,
                                     uint32_t *decrypted_bytes);

/* Finish the chunk-based decryption session. Returns the status. Writes the
   final decrypted data to the c_state buffer and sets *decrypted_off to the
   offset in the c_state buffer of the final decrypted data and sets
   *decrypted_bytes to the length of the final part of the decrypted data. The
   c_state is no longer usable for a chunk-based decryption session until
   mte_mke_dec_decrypt_start() is called.

   The timestamp callback and context are used to obtain the timestamp if the
   timestamp verifier is enabled. */
MTE_SHARED
mte_status mte_mke_dec_decrypt_finish(MTE_HANDLE state, MTE_HANDLE c_state,
                                      mte_verifier_get_timestamp64 t_cb,
                                      void *t_cb_context,
                                      uint32_t *decrypted_off,
                                      uint32_t *decrypted_bytes);

/* Returns the encode/decode timestamp from the most recent decode. */
MTE_SHARED
uint64_t mte_mke_dec_enc_ts(MTE_CHANDLE state);
MTE_SHARED
uint64_t mte_mke_dec_dec_ts(MTE_CHANDLE state);

/* If the sequence window is non-negative, returns the messages skipped from the
   most recent decode; otherwise it returns the number of messages ahead of the
   base sequence from the most recent decode. */
MTE_SHARED MTE_WASM_EXPORT
uint32_t mte_mke_dec_msg_skipped(MTE_CHANDLE state);

/* Uninstantiate the decoder. Returns the status. */
MTE_SHARED MTE_WASM_EXPORT
mte_status mte_mke_dec_uninstantiate(MTE_HANDLE state);

#ifdef __cplusplus
}
#endif

#endif


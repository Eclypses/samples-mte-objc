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
#ifndef mte_wrap_base_h
#define mte_wrap_base_h

#ifndef mte_base_h
#include "mte_base.h"
#endif

/* This wraps the MTE base functions.

   To use with a dynamic library, compile with MTE_BUILD_SHARED defined.
*/
#ifdef __cplusplus
extern "C"
{
#endif

/* The entropy input callback signature for wrappers. */
typedef mte_status (*mte_wrap_get_entropy_input)(void *context,
                                                 MTE_UINT32_T min_entropy,
                                                 MTE_UINT32_T min_length,
                                                 MTE_UINT64_T max_length,
                                                 MTE_UINT8_T **entropy_input,
                                                 MTE_UINT64_T *ei_bytes);

/* The nonce callback signature for wrappers. */
typedef void (*mte_wrap_get_nonce)(void *context,
                                   MTE_UINT32_T min_length,
                                   MTE_UINT32_T max_length,
                                   void *nonce,
                                   MTE_UINT32_T *n_bytes);

/* Returns the MTE version number as individual integer parts. */
MTE_SHARED
MTE_UINT32_T mte_wrap_base_version_major(void);
MTE_SHARED
MTE_UINT32_T mte_wrap_base_version_minor(void);
MTE_SHARED
MTE_UINT32_T mte_wrap_base_version_patch(void);

/* Returns the count of status codes. */
MTE_SHARED
MTE_UINT32_T mte_wrap_base_status_count(void);

/* Returns the enumeration name for the given status. */
MTE_SHARED
const char *mte_wrap_base_status_name(mte_status status);

/* Returns the description for the given status. */
MTE_SHARED
const char *mte_wrap_base_status_description(mte_status status);

/* Returns the status code for the given enumeration name. */
MTE_SHARED
mte_status mte_wrap_base_status_code(const char *name);

/* Returns MTE_TRUE if runtime options are available or MTE_FALSE if not. */
MTE_SHARED
MTE_BOOL mte_wrap_base_has_runtime_opts(void);

/* Returns the default DRBG. If runtime options are not available, this is
   the only option available; otherwise it is a suitable default. */
MTE_SHARED
mte_drbgs mte_wrap_base_default_drbg(void);

/* Returns the default token size. If runtime options are not available, this
   is the only option available; otherwise it is a suitable default. */
MTE_SHARED
uint32_t mte_wrap_base_default_tok_bytes(void);

/* Returns the default verifiers. If runtime options are not available, this
   is the only option available; otherwise it is a suitable default. */
MTE_SHARED
mte_verifiers mte_wrap_base_default_verifiers(void);

/* Returns the default cipher. If runtime options are not available, this is
   the only option available; otherwise it is a suitable default. */
MTE_SHARED
mte_ciphers mte_wrap_base_default_cipher(void);

/* Returns the default hash. If runtime options are not available, this is
   the only option available; otherwise it is a suitable default. */
MTE_SHARED
mte_hashes mte_wrap_base_default_hash(void);

/* Returns the count of DRBG algorithms. */
MTE_SHARED
MTE_UINT32_T mte_wrap_base_drbgs_count(void);

/* Returns the enumeration name for the given algorithm. */
MTE_SHARED
const char *mte_wrap_base_drbgs_name(mte_drbgs algo);

/* Returns the algorithm for the given enumeration name. */
MTE_SHARED
mte_drbgs mte_wrap_base_drbgs_algo(const char *name);

/* Returns the security strength for the given algorithm. */
MTE_SHARED
MTE_UINT32_T mte_wrap_base_drbgs_sec_strength_bytes(mte_drbgs algo);

/* Returns the minimum/maximum personalization string size for the given
   algorithm. */
MTE_SHARED
MTE_UINT32_T mte_wrap_base_drbgs_personal_min_bytes(mte_drbgs algo);
MTE_SHARED
MTE_UINT64_T mte_wrap_base_drbgs_personal_max_bytes(mte_drbgs algo);

/* Returns the minimum/maximum entropy size for the given algorithm. */
MTE_SHARED
MTE_UINT32_T mte_wrap_base_drbgs_entropy_min_bytes(mte_drbgs algo);
MTE_SHARED
MTE_UINT64_T mte_wrap_base_drbgs_entropy_max_bytes(mte_drbgs algo);

/* Returns the minimum/maximum nonce size for the given algorithm. */
MTE_SHARED
MTE_UINT32_T mte_wrap_base_drbgs_nonce_min_bytes(mte_drbgs algo);
MTE_SHARED
MTE_UINT32_T mte_wrap_base_drbgs_nonce_max_bytes(mte_drbgs algo);

/* Returns the reseed interval for the given algorithm. */
MTE_SHARED
MTE_UINT64_T mte_wrap_base_drbgs_reseed_interval(mte_drbgs algo);

/* Set the increment DRBG to return an error during instantiation and
   uninstantiation (if MTE_TRUE) or not (if MTE_FALSE). This is useful for
   testing error handling. The flag is MTE_FALSE until set with this. */
MTE_SHARED
void mte_wrap_base_drbgs_incr_inst_error(MTE_BOOL flag);

/* Set the increment DRBG to produce an error after the given number of values
   have been generated (if flag is MTE_TRUE) or turn off errors (if flag is
   MTE_FALSE) other than the reseed error, which is always produced when the
   seed interval is reached. The flag is MTE_FALSE until set with this. */
MTE_SHARED
void mte_wrap_base_drbgs_incr_gen_error(MTE_BOOL flag, MTE_UINT32_T after);

/* Returns the count of verifier algorithms. */
MTE_SHARED
MTE_UINT32_T mte_wrap_base_verifiers_count(void);

/* Returns the enumeration name for the given algorithm. */
MTE_SHARED
const char *mte_wrap_base_verifiers_name(mte_verifiers algo);

/* Returns the algorithm for the given name. */
MTE_SHARED
mte_verifiers mte_wrap_base_verifiers_algo(const char *name);

/* Returns the count of cipher algorithms. */
MTE_SHARED
MTE_UINT32_T mte_wrap_base_ciphers_count(void);

/* Returns the enumeration name for the given algorithm. */
MTE_SHARED
const char *mte_wrap_base_ciphers_name(mte_ciphers algo);

/* Returns the algorithm for the given name. */
MTE_SHARED
mte_ciphers mte_wrap_base_ciphers_algo(const char *name);

/* Returns the block size for the given algorithm. */
MTE_SHARED
MTE_UINT32_T mte_wrap_base_ciphers_block_bytes(mte_ciphers algo);

/* Returns the count of hash algorithms. */
MTE_SHARED
MTE_UINT32_T mte_wrap_base_hashes_count(void);

/* Returns the enumeration name for the given algorithm. */
MTE_SHARED
const char *mte_wrap_base_hashes_name(mte_hashes algo);

/* Returns the algorithm for the given name. */
MTE_SHARED
mte_hashes mte_wrap_base_hashes_algo(const char *name);

#ifdef __cplusplus
}
#endif

#endif


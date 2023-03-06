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
#ifndef mte_drbg_defs_h
#define mte_drbg_defs_h

#ifndef mte_int_h
#include "mte_int.h"
#endif
#ifndef mte_status_h
#include "mte_status.h"
#endif

/* This has common random number generator definitions. */
#ifdef __cplusplus
extern "C"
{
#endif

/* The Get_entropy_input() function. NIST SP 800-90A section 9. Prediction
   resistance is not supported. The sizes are all specified in bytes, not bits.
   The *entropy_input pointer must point at a buffer of at least min_length
   bytes. When called, *ei_bytes must be set to the actual buffer length that
   *entropy_input points to. The function must do the following:
   - If min_length entropy cannot be generated, return a catastrophic error.
   - If at least min_length and no more than *ei_bytes entropy is generated,
     fill in the *entropy_input, set the *ei_bytes to the actual entropy
     length, and return success.
   - If more than *ei_bytes of entropy is generated, set *entropy_input to your
     buffer of entropy, set *ei_bytes to the actual entropy length, and return
     success.
   - It is also acceptable to set *entropy_input to your buffer even if it is
     less than or equal to *ei_bytes instead of copying to the provided buffer.
   The context pointer is simply passed through from the function that calls
   the callback. */
typedef mte_status (*mte_drbg_get_entropy_input)(void *context,
                                                 uint32_t min_entropy,
                                                 uint32_t min_length,
                                                 uint64_t max_length,
                                                 uint8_t **entropy_input,
                                                 uint64_t *ei_bytes);

/* Get a nonce of at least min_length and no more than max_length bytes. The
   nonce pointer must point at a buffer of at least max_length bytes. The
   function must fill in the nonce and set *n_bytes to the actual nonce length
   in bytes. The context pointer is simply passed through from the function
   that calls the callback. */
typedef void (*mte_drbg_get_nonce)(void *context,
                                   uint32_t min_length,
                                   uint32_t max_length,
                                   void *nonce,
                                   uint32_t *n_bytes);

/* Instantiate the DRBG given the entropy input callback/context, nonce
   callback/context, personalization string and length of the personalization
   string in bytes. Returns the status. */
typedef mte_status (*mte_drbg_instantiate)(void *state,
                                           mte_drbg_get_entropy_input ei_cb,
                                           void *ei_cb_context,
                                           mte_drbg_get_nonce n_cb,
                                           void *n_cb_context,
                                           const void *ps,
                                           uint32_t ps_bytes);

/* Returns the current reseed counter value. */
typedef uint64_t (*mte_drbg_reseed_counter)(const void *state);

/* Returns the size required to save the state. */
typedef uint32_t (*mte_drbg_state_save_bytes)(void);

/* Save the DRBG state to the given buffer. */
typedef void (*mte_drbg_state_save)(const void *state, void *saved);

/* Restore the DRBG state from the given buffer. */
typedef void (*mte_drbg_state_restore)(void *state, const void *saved);

/* Generate a random number of the requested length in bytes, placing it in the
   random_number buffer. Returns the status. */
typedef mte_status (*mte_drbg_generate)(void *state,
                                        uint32_t requested_number_of_bytes,
                                        void *random_number);

/* Uninstantiate the DRBG. Returns the status. */
typedef mte_status (*mte_drbg_uninstantiate)(void *state);

#ifdef __cplusplus
}
#endif

#endif


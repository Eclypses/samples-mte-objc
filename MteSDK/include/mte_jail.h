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
#ifndef mte_jail_h
#define mte_jail_h

#ifndef mte_base_h
#include "mte_base.h"
#endif

/* Jailbreak detection functions.

   To use with a dynamic library, compile with MTE_BUILD_SHARED defined.

   Each function mutates the nonce in some way to change the MTE initialization
   so communication will only succeed if the paired MTE initialized the same
   way. The mutation depends on the jailbreak detection algorithm producing
   certain results.

   There is a separate function for each tuple of OS, architecture, and
   simulator/device, since the detection is highly dependent on these factors.
   The device versions end with _d; the simulator versions end with _s.

   All functions have two implementations, depending where they run. On a device
   that can be jailbroken (e.g., a phone), the implementation does jailbreak
   detection to mutate the nonce. On a device that cannot be jailbroken (e.g., a
   normal computer), the implementation simulates successful jailbreak detection
   for the associated device type.

   The same nonce mutator must be used on the encoder and decoder in order to
   successfully pair the two devices.

   Example: iPhone (ARM64) encoder communicating with Linux (x86_64) decoder:
            Both should use mte_jail_n_cb_ios_arm64_d.

   Example: iPhone Simulator (x86_64) encoder communicating with Linux (x86_64)
            decoder: Both should use mte_jail_n_cb_ios_x86_64_s.

   Note that using a nonce mutator that does not match the actual device OS and
   architecture will not do any jailbreak detection. It will just do simulation
   for communicating with an actual device of that type.

   For security, devices that can be jailbroken cannot simulate jailbreak
   detection (of a different device type). Attempting to do so has the same
   effect as a failed jailbreak detection, meaning no valid communication.
*/
#ifdef __cplusplus
extern "C"
{
#endif

/* Definition of a jailbreak nonce mutator. */
typedef void (*mte_jail_mutator)(const void *seed,
                                 MTE_SIZE8_T seed_bytes,
                                 MTE_SIZE8_T min_length,
                                 MTE_SIZE8_T max_length,
                                 void *nonce,
                                 MTE_SIZE8_T *n_bytes);

/* Jailbreak detection nonce mutator for an Android device. The min_length,
   max_length, nonce, and n_bytes should be passed through from the nonce
   callback. The seed and seed_bytes are used to provide your seed nonce which
   will be mutated during jailbreak detection and the mutated nonce is set in
   nonce and n_bytes. */
MTE_SHARED MTE_WASM_EXPORT
void mte_jail_n_cb_android_arm32_d(const void *seed,
                                   MTE_SIZE8_T seed_bytes,
                                   MTE_SIZE8_T min_length,
                                   MTE_SIZE8_T max_length,
                                   void *nonce,
                                   MTE_SIZE8_T *n_bytes);
MTE_SHARED MTE_WASM_EXPORT
void mte_jail_n_cb_android_arm64_d(const void *seed,
                                   MTE_SIZE8_T seed_bytes,
                                   MTE_SIZE8_T min_length,
                                   MTE_SIZE8_T max_length,
                                   void *nonce,
                                   MTE_SIZE8_T *n_bytes);

/* Jailbreak detection nonce mutator for an Android simulator. The min_length,
   max_length, nonce, and n_bytes should be passed through from the nonce
   callback. The seed and seed_bytes are used to provide your seed nonce which
   will be mutated during jailbreak detection and the mutated nonce is set in
   nonce and n_bytes. */
MTE_SHARED MTE_WASM_EXPORT
void mte_jail_n_cb_android_x86_s(const void *seed,
                                 MTE_SIZE8_T seed_bytes,
                                 MTE_SIZE8_T min_length,
                                 MTE_SIZE8_T max_length,
                                 void *nonce,
                                 MTE_SIZE8_T *n_bytes);
MTE_SHARED MTE_WASM_EXPORT
void mte_jail_n_cb_android_x86_64_s(const void *seed,
                                    MTE_SIZE8_T seed_bytes,
                                    MTE_SIZE8_T min_length,
                                    MTE_SIZE8_T max_length,
                                    void *nonce,
                                    MTE_SIZE8_T *n_bytes);

/* Jailbreak detection nonce mutator for an iOS device. The min_length,
   max_length, nonce, and n_bytes should be passed through from the nonce
   callback. The seed and seed_bytes are used to provide your seed nonce which
   will be mutated during jailbreak detection and the mutated nonce is set in
   nonce and n_bytes. */
MTE_SHARED MTE_WASM_EXPORT
void mte_jail_n_cb_ios_arm64_d(const void *seed,
                               MTE_SIZE8_T seed_bytes,
                               MTE_SIZE8_T min_length,
                               MTE_SIZE8_T max_length,
                               void *nonce,
                               MTE_SIZE8_T *n_bytes);

/* Jailbreak detection nonce mutator for an iOS simulator. The min_length,
   max_length, nonce, and n_bytes should be passed through from the nonce
   callback. The seed and seed_bytes are used to provide your seed nonce which
   will be mutated during jailbreak detection and the mutated nonce is set in
   nonce and n_bytes. */
MTE_SHARED MTE_WASM_EXPORT
void mte_jail_n_cb_ios_x86_64_s(const void *seed,
                                MTE_SIZE8_T seed_bytes,
                                MTE_SIZE8_T min_length,
                                MTE_SIZE8_T max_length,
                                void *nonce,
                                MTE_SIZE8_T *n_bytes);

#ifdef __cplusplus
}
#endif

#endif


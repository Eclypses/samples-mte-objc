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
#ifndef mte_wrap_jail_h
#define mte_wrap_jail_h

#ifndef mte_export_h
#include "mte_export.h"
#endif
#ifndef mte_int_h
#include "mte_int.h"
#endif

/* This wraps the MTE jailbreak detection add-on encoder functions.

 To use with a dynamic library, compile with MTE_BUILD_SHARED defined.
*/
#ifdef __cplusplus
extern "C"
{
#endif

/* Jailbreak detection nonce mutator for an Android device. The min_length,
   max_length, nonce, and n_bytes should be passed through from the nonce
   callback. The seed and seed_bytes are used to provide your seed nonce which
   will be mutated during jailbreak detection and the mutated nonce is set in
   nonce and n_bytes. */
MTE_SHARED
void mte_wrap_jail_n_cb_android_arm32_d(const void *seed,
                                        MTE_UINT32_T seed_bytes,
                                        MTE_UINT32_T min_length,
                                        MTE_UINT32_T max_length,
                                        void *nonce,
                                        MTE_UINT32_T *n_bytes);
MTE_SHARED
void mte_wrap_jail_n_cb_android_arm64_d(const void *seed,
                                        MTE_UINT32_T seed_bytes,
                                        MTE_UINT32_T min_length,
                                        MTE_UINT32_T max_length,
                                        void *nonce,
                                        MTE_UINT32_T *n_bytes);

/* Jailbreak detection nonce mutator for an Android simulator. The min_length,
   max_length, nonce, and n_bytes should be passed through from the nonce
   callback. The seed and seed_bytes are used to provide your seed nonce which
   will be mutated during jailbreak detection and the mutated nonce is set in
   nonce and n_bytes. */
MTE_SHARED
void mte_wrap_jail_n_cb_android_x86_s(const void *seed,
                                      MTE_UINT32_T seed_bytes,
                                      MTE_UINT32_T min_length,
                                      MTE_UINT32_T max_length,
                                      void *nonce,
                                      MTE_UINT32_T *n_bytes);
MTE_SHARED
void mte_wrap_jail_n_cb_android_x86_64_s(const void *seed,
                                         MTE_UINT32_T seed_bytes,
                                         MTE_UINT32_T min_length,
                                         MTE_UINT32_T max_length,
                                         void *nonce,
                                         MTE_UINT32_T *n_bytes);

/* Jailbreak detection nonce mutator for an iOS device. The min_length,
   max_length, nonce, and n_bytes should be passed through from the nonce
   callback. The seed and seed_bytes are used to provide your seed nonce which
   will be mutated during jailbreak detection and the mutated nonce is set in
   nonce and n_bytes. */
MTE_SHARED
void mte_wrap_jail_n_cb_ios_arm64_d(const void *seed,
                                    MTE_UINT32_T seed_bytes,
                                    MTE_UINT32_T min_length,
                                    MTE_UINT32_T max_length,
                                    void *nonce,
                                    MTE_UINT32_T *n_bytes);

/* Jailbreak detection nonce mutator for an iOS simulator. The min_length,
   max_length, nonce, and n_bytes should be passed through from the nonce
   callback. The seed and seed_bytes are used to provide your seed nonce which
   will be mutated during jailbreak detection and the mutated nonce is set in
   nonce and n_bytes. */
MTE_SHARED
void mte_wrap_jail_n_cb_ios_x86_64_s(const void *seed,
                                     MTE_UINT32_T seed_bytes,
                                     MTE_UINT32_T min_length,
                                     MTE_UINT32_T max_length,
                                     void *nonce,
                                     MTE_UINT32_T *n_bytes);

#ifdef __cplusplus
}
#endif

#endif


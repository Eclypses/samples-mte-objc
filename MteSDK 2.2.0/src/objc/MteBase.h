// The MIT License (MIT)
//
// Copyright (c) Eclypses, Inc.
//
// All rights reserved.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in 
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
#import "mte_base.h"
#import <Foundation/Foundation.h>

// Interface of an entropy input callback.
@protocol MteEntropyCallback
-(mte_status)entropyCallbackWithMinEntropy:(uint32_t)minEntropy
                                 minLength:(uint32_t)minLength
                                 maxLength:(uint64_t)maxLength
                              entropyInput:(uint8_t **)entropyInput
                                   eiBytes:(uint64_t *)eiBytes;
@end

// Interface of a nonce callback.
@protocol MteNonceCallback
-(void)nonceCallbackWithMinLength:(uint32_t)minLength
                        maxLength:(uint32_t)maxLength
                            nonce:(void *)nonce
                           nBytes:(uint32_t *)nBytes;
@end

// Interface of a timestamp callback.
@protocol MteTimestampCallback
-(uint64_t)timestampCallback;
@end

// Class MteBase
//
// This is the base for all MTE classes.
//
// To use, call any of the static helper functions and/or derive from this
// class. Derived implementations may want to override the callbacks for
// providing entropy, a nonce, and a timestamp, depending on their needs.
// Derived classes must send the
// -initBase:tokBytes:byteValMin:byteValCount:verifers:cipher:hash: message to
// initialize.
//
// The MTE initialization is automatically performed unless built with
// MTE_SKIP_AUTO_INIT defined, in which case you must do the initialization
// yourself.
@interface MteBase : NSObject
{
  // Options.
  mte_drbgs myDrbg;
  size_t myTokBytes;
  mte_verifiers myVerifiers;
  mte_ciphers myCipher;
  mte_hashes myHash;

  // Entropy, nonce, and timestamp delegates.
  id<MteEntropyCallback> myEntropyCb;
  id<MteNonceCallback> myNonceCb;
  id<MteTimestampCallback> myTimestampCb;

  // Instantiation inputs.
  void *myEntropyInput;
  size_t myEntropyInputBytes;
  const void *myNonce;
  size_t myNonceBytes;
  uint8_t myNonceBuff[32];

  // Nonce length when set as an integer.
  size_t myNonceIntBytes;
}

// Returns the MTE version number as a string or individual integer parts.
+(NSString *)getVersion;
+(size_t)getVersionMajor;
+(size_t)getVersionMinor;
+(size_t)getVersionPatch;

#ifndef MTE_SKIP_AUTO_INIT
+(void)load;
#endif

// Initialize with the company name and license code. Returns true if
// successful or false if not. If true is returned, MTE functions are usable;
// otherwise functions that return a status will return an error status.
+(BOOL)initLicense:(NSString *)company code:(NSString *)license;

// Returns the count of status codes.
+(size_t)getStatusCount;

// Returns the enumeration name for the given status.
+(NSString *)getStatusName:(mte_status)status;

// Returns the description for the given status.
+(NSString *)getStatusDescription:(mte_status)status;

// Returns the status code for the given enumeration name.
+(mte_status)getStatusCode:(NSString *)name;

// Returns true if the given status is an error, false if it is success or a
// warning.
+(BOOL)statusIsError:(mte_status)status;

// Returns true if buildtime options are chosen or false if runtime options
// are available. If buildtime options are chosen, they can be queried with
// the additional buildtime accessors.
+(BOOL)hasBuildtimeOpts;

// Returns the DRBG buildtime option if buildtime options are chosen; otherwise
// mte_drbgs_none is returned.
+(mte_drbgs)getBuildtimeDrbg;

// Returns the token size buildtime option if buildtime options are chosen;
// otherwise 0 is returned.
+(size_t)getBuildtimeTokBytes;

// Returns the verifiers buildtime option if buildtime options are chosen;
// otherwise mte_verifiers_none is returned.
+(mte_verifiers)getBuildtimeVerifiers;

// Returns the cipher buildtime option if buildtime options are chosen;
// otherwise mte_ciphers_none is returned.
+(mte_ciphers)getBuildtimeCipher;

// Returns the hash buildtime option if buildtime options are chosen; otherwise
// mte_hashes_none is returned.
+(mte_hashes)getBuildtimeHash;

// Returns the count of DRBG algorithms.
+(size_t)getDrbgsCount;

// Returns the enumeration name for the given algorithm.
+(NSString *)getDrbgsName:(mte_drbgs)algo;

// Returns the algorithm for the given enumeration name.
+(mte_drbgs)getDrbgsAlgo:(NSString *)name;

// Returns the security strength for the given algorithm.
+(size_t)getDrbgsSecStrengthBytes:(mte_drbgs)algo;

// Returns the minimum/maximum personalization string size for the given
// algorithm.
+(size_t)getDrbgsPersonalMinBytes:(mte_drbgs)algo;
+(uint64_t)getDrbgsPersonalMaxBytes:(mte_drbgs)algo;

// Returns the minimum/maximum entropy size for the given algorithm.
+(size_t)getDrbgsEntropyMinBytes:(mte_drbgs)algo;
+(uint64_t)getDrbgsEntropyMaxBytes:(mte_drbgs)algo;

// Returns the minimum/maximum nonce size for the given algorithm.
+(size_t)getDrbgsNonceMinBytes:(mte_drbgs)algo;
+(size_t)getDrbgsNonceMaxBytes:(mte_drbgs)algo;

// Returns the reseed interval for the given algorithm.
+(uint64_t)getDrbgsReseedInterval:(mte_drbgs)algo;

// Set the increment DRBG to return an error during instantiation and
// uninstantiation (if YES) or not (if NO). This is useful for testing error
// handling. The flag is false until set with this.
+(void)setIncrInstError:(BOOL)flag;

// Set the increment DRBG to produce an error after the given number of values
// have been generated (if flag is YES) or turn off errors (if flag is NO)
// other than the reseed error, which is always produced when the seed interval
// is reached. The flag is NO until set with this.
+(void)setIncrGenError:(BOOL)flag after:(size_t)after;

// Returns the count of verifier algorithms.
+(size_t)getVerifiersCount;

// Returns the enumeration name for the given algorithm.
+(NSString *)getVerifiersName:(mte_verifiers)algo;

// Returns the algorithm for the given enumeration name.
+(mte_verifiers)getVerifiersAlgo:(NSString *)name;

// Returns the count of cipher algorithms.
+(size_t)getCiphersCount;

// Returns the enumeration name for the given algorithm.
+(NSString *)getCiphersName:(mte_ciphers)algo;

// Returns the algorithm for the given enumeration name.
+(mte_ciphers)getCiphersAlgo:(NSString *)name;

// Returns the block size for the given algorithm.
+(size_t)getCiphersBlockBytes:(mte_ciphers)algo;

// Returns the count of hash algorithms.
+(size_t)getHashesCount;

// Returns the enumeration name for the given algorithm.
+(NSString *)getHashesName:(mte_hashes)algo;

// Returns the algorithm for the given enumeration name.
+(mte_hashes)getHashesAlgo:(NSString *)name;

// Return the options in use.
-(mte_drbgs)getDrbg;
-(size_t)getTokBytes;
-(mte_verifiers)getVerifiers;
-(mte_ciphers)getCipher;
-(mte_hashes)getHash;

// Set the entropy callback. If not nil, it is called to get entropy. If
// nil, the entropy set with setEntropy() is used. No ownership is taken.
// The cb object must remain valid for the lifetime of this object.
-(void)setEntropyCallback:(id<MteEntropyCallback>)cb;

// Set the entropy input value. This must be done before calling an
// instantiation method that will trigger the entropy callback. The value must
// remain valid until initialization completes.
//
// The entropy is zeroized when used by an instantiation call.
//
// All ownership remains with the caller. If the entropy callback is nil,
// entropyInput is used as the entropy.
-(void)setEntropy:(void *)entropyInput bytes:(size_t)eiBytes;

// Set the nonce callback. If not nil, it is used to get the nonce. If nil,
// the nonce set with setNonce: is used.
-(void)setNonceCallback:(id<MteNonceCallback>)cb;

// Set the nonce. This must be done before calling an instantiation method
// that will trigger the nonce callback.
//
// All ownership remains with the caller. If the nonce callback is nil,
// nonce is used as the nonce.
-(void)setNonce:(const void *)nonce bytes:(size_t)nBytes;

// Sends setNonce:bytes: with the nonce value as an array of bytes in little
// endian format.
-(void)setNonce:(uint64_t)nonce;

// Set the timestamp callback. If not nil, it is called to get the timestamp.
// If nil, 0 is used.
-(void)setTimestampCallback:(id<MteTimestampCallback>)cb;

// The entropy callback.
-(mte_status)entropyCallbackWithMinEntropy:(uint32_t)minEntropy
                                 minLength:(uint32_t)minLength
                                 maxLength:(uint64_t)maxLength
                              entropyInput:(uint8_t **)entropyInput
                                   eiBytes:(uint64_t *)eiBytes;

// The nonce callback.
-(void)nonceCallbackWithMinLength:(uint32_t)minLength
                        maxLength:(uint32_t)maxLength
                            nonce:(void *)nonce
                           nBytes:(uint32_t *)nBytes;

// The timestamp callback.
-(uint64_t)timestampCallback;

// Initialize.
-(id)initBase:(mte_drbgs)drbg
     tokBytes:(size_t)tokBytes
    verifiers:(mte_verifiers)verifiers
       cipher:(mte_ciphers)cipher
         hash:(mte_hashes)hash;

@end

// C callbacks.
mte_status MteBaseEntropyCallback(void *context,
                                  uint32_t min_entropy,
                                  uint32_t min_length,
                                  uint64_t max_length,
                                  uint8_t **entropy_input,
                                  uint64_t *ei_bytes);

void MteBaseNonceCallback(void *context,
                          uint32_t min_length,
                          uint32_t max_length,
                          void *nonce,
                          uint32_t *n_bytes);

uint64_t MteBaseTimestampCallback(void *context);

// Default options.
#define MTE_BASE_DEFAULT_DRBG mte_drbgs_ctr_aes256_df
#define MTE_BASE_DEFAULT_TOKBYTES 16
#define MTE_BASE_DEFAULT_VERIFIERS mte_verifiers_t64_crc32_seq
#define MTE_BASE_DEFAULT_CIPHER mte_ciphers_aes256_ctr
#define MTE_BASE_DEFAULT_HASH mte_hashes_sha256

// Handle operations that differ if ARC is enabled.
#if __has_feature(objc_arc)
#  define MTE_AUTORELEASE(x) (x)
#  define MTE_SUP_DEALLOC()
#else
#  define MTE_AUTORELEASE(x) [(x) autorelease]
#  define MTE_SUP_DEALLOC() [super dealloc]
#endif


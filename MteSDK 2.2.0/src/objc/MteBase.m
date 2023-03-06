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
#import "MteBase.h"
#import "mte_base.h"
#import "mte_init.h"
#import "mte_license.h"
#import "mte_version.h"

@implementation MteBase

+(NSString *)getVersion
{
  NSString *str = [[NSString alloc] initWithUTF8String:mte_base_version()];
  return MTE_AUTORELEASE(str);
}

+(size_t)getVersionMajor
{
  return mte_base_version_major();
}

+(size_t)getVersionMinor
{
  return mte_base_version_minor();
}

+(size_t)getVersionPatch
{
  return mte_base_version_patch();
}

#ifndef MTE_SKIP_AUTO_INIT
+(void)load
{
  // Do global init.
  if (!mte_init(NULL, NULL))
  {
    [NSException raise:NSGenericException
                format:@"MteBase load: MTE init error."];
  }

  // Check version.
  if (mte_base_version_major() != MTE_VERSION_MAJOR ||
      mte_base_version_minor() != MTE_VERSION_MINOR ||
      mte_base_version_patch() != MTE_VERSION_PATCH)
  {
    [NSException raise:NSInternalInconsistencyException
                format:@"MteBase load: MTE version mismatch."];
  }
}
#endif

+(BOOL)initLicense:(NSString *)company code:(NSString *)license
{
  return mte_license_init([company UTF8String],
                          [license UTF8String]) == MTE_FALSE ? NO : YES;
}

+(size_t)getStatusCount
{
  return mte_base_status_count();
}

+(NSString *)getStatusName:(mte_status)status
{
  NSString *str = [[NSString alloc]
                   initWithUTF8String:mte_base_status_name(status)];
  return MTE_AUTORELEASE(str);
}

+(NSString *)getStatusDescription:(mte_status)status
{
  NSString *str = [[NSString alloc]
                   initWithUTF8String:mte_base_status_description(status)];
  return MTE_AUTORELEASE(str);
}

+(mte_status)getStatusCode:(NSString *)name
{
  return mte_base_status_code([name UTF8String]);
}

+(BOOL)statusIsError:(mte_status)status
{
  return mte_base_status_is_error(status) != MTE_FALSE;
}

+(BOOL)hasBuildtimeOpts
{
  return mte_base_has_buildtime_opts() != 0;
}

+(mte_drbgs)getBuildtimeDrbg
{
  return mte_base_buildtime_drbg();
}

+(size_t)getBuildtimeTokBytes
{
  return mte_base_buildtime_tok_bytes();
}

+(mte_verifiers)getBuildtimeVerifiers
{
  return mte_base_buildtime_verifiers();
}

+(mte_ciphers)getBuildtimeCipher
{
  return mte_base_buildtime_cipher();
}

+(mte_hashes)getBuildtimeHash
{
  return mte_base_buildtime_hash();
}

+(size_t)getDrbgsCount
{
  return mte_base_drbgs_count();
}

+(NSString *)getDrbgsName:(mte_drbgs)algo
{
  NSString *str = [[NSString alloc]
                   initWithUTF8String:mte_base_drbgs_name(algo)];
  return MTE_AUTORELEASE(str);
}

+(mte_drbgs)getDrbgsAlgo:(NSString *)name
{
  return mte_base_drbgs_algo([name UTF8String]);
}

+(size_t)getDrbgsSecStrengthBytes:(mte_drbgs)algo
{
  return mte_base_drbgs_sec_strength_bytes(algo);
}

+(size_t)getDrbgsPersonalMinBytes:(mte_drbgs)algo
{
  return mte_base_drbgs_personal_min_bytes(algo);
}

+(uint64_t)getDrbgsPersonalMaxBytes:(mte_drbgs)algo
{
  return mte_base_drbgs_personal_max_bytes(algo);
}

+(size_t)getDrbgsEntropyMinBytes:(mte_drbgs)algo
{
  return mte_base_drbgs_entropy_min_bytes(algo);
}

+(uint64_t)getDrbgsEntropyMaxBytes:(mte_drbgs)algo
{
  return mte_base_drbgs_entropy_max_bytes(algo);
}

+(size_t)getDrbgsNonceMinBytes:(mte_drbgs)algo
{
  return mte_base_drbgs_nonce_min_bytes(algo);
}

+(size_t)getDrbgsNonceMaxBytes:(mte_drbgs)algo
{
  return mte_base_drbgs_nonce_max_bytes(algo);
}

+(uint64_t)getDrbgsReseedInterval:(mte_drbgs)algo
{
  return mte_base_drbgs_reseed_interval(algo);
}

+(void)setIncrInstError:(BOOL)flag
{
  mte_base_drbgs_incr_inst_error(flag ? MTE_TRUE : MTE_FALSE);
}

+(void)setIncrGenError:(BOOL)flag after:(size_t)after
{
  mte_base_drbgs_incr_gen_error(flag ? MTE_TRUE : MTE_FALSE, (uint32_t)after);
}

+(size_t)getVerifiersCount
{
  return mte_base_verifiers_count();
}

+(NSString *)getVerifiersName:(mte_verifiers)algo
{
  NSString *str = [[NSString alloc]
                   initWithUTF8String:mte_base_verifiers_name(algo)];
  return MTE_AUTORELEASE(str);
}

+(mte_verifiers)getVerifiersAlgo:(NSString *)name
{
  return mte_base_verifiers_algo([name UTF8String]);
}

+(size_t)getCiphersCount
{
  return mte_base_ciphers_count();
}

+(NSString *)getCiphersName:(mte_ciphers)algo
{
  NSString *str = [[NSString alloc]
                   initWithUTF8String:mte_base_ciphers_name(algo)];
  return MTE_AUTORELEASE(str);
}

+(mte_ciphers)getCiphersAlgo:(NSString *)name
{
  return mte_base_ciphers_algo([name UTF8String]);
}

+(size_t)getCiphersBlockBytes:(mte_ciphers)algo
{
  return mte_base_ciphers_block_bytes(algo);
}

+(size_t)getHashesCount
{
  return mte_base_hashes_count();
}

+(NSString *)getHashesName:(mte_hashes)algo
{
  NSString *str = [[NSString alloc]
                   initWithUTF8String:mte_base_hashes_name(algo)];
  return MTE_AUTORELEASE(str);
}

+(mte_hashes)getHashesAlgo:(NSString *)name
{
  return mte_base_hashes_algo([name UTF8String]);
}

-(mte_drbgs)getDrbg
{
  return myDrbg;
}

-(size_t)getTokBytes
{
  return myTokBytes;
}

-(mte_verifiers)getVerifiers
{
  return myVerifiers;
}

-(mte_ciphers)getCipher
{
  return myCipher;
}

-(mte_hashes)getHash
{
  return myHash;
}

-(void)setEntropyCallback:(id<MteEntropyCallback>)cb
{
  myEntropyCb = cb;
}

-(void)setEntropy:(void *)entropyInput bytes:(size_t)eiBytes
{
  myEntropyInput = entropyInput;
  myEntropyInputBytes = eiBytes;
}

-(void)setNonceCallback:(id<MteNonceCallback>)cb
{
  myNonceCb = cb;
}

-(void)setNonce:(const void *)nonce bytes:(size_t)nBytes
{
  myNonce = nonce;
  myNonceBytes = nBytes;
}

-(void)setNonce:(uint64_t)nonce
{
  // Copy the bytes of the nonce in little endian.
  size_t i = 0;
  for (; i < sizeof(nonce); ++i)
  {
    myNonceBuff[i] = (uint8_t)(nonce >> (i * 8));
  }

  // If the nonce must be longer, zero pad.
  for (; i < myNonceIntBytes; ++i)
  {
    myNonceBuff[i] = 0;
  }

  // Set the nonce to the ideal size.
  [self setNonce:myNonceBuff bytes:myNonceIntBytes];
}

-(void)setTimestampCallback:(id<MteTimestampCallback>)cb
{
  myTimestampCb = cb;
}

-(mte_status)entropyCallbackWithMinEntropy:(uint32_t)minEntropy
                                 minLength:(uint32_t)minLength
                                 maxLength:(uint64_t)maxLength
                              entropyInput:(uint8_t **)entropyInput
                                   eiBytes:(uint64_t *)eiBytes
{
  // Call the callback if set.
  if (myEntropyCb != nil)
  {
    return [myEntropyCb entropyCallbackWithMinEntropy:minEntropy
                                            minLength:minLength
                                            maxLength:maxLength
                                         entropyInput:entropyInput
                                              eiBytes:eiBytes];
  }

  // Check the length.
  if (myEntropyInputBytes < minLength || myEntropyInputBytes > maxLength)
  {
    return mte_status_drbg_catastrophic;
  }

  // Just point at the entropy buffer.
  *entropyInput = (uint8_t *)myEntropyInput;

  // Success.
  *eiBytes = myEntropyInputBytes;
  return mte_status_success;
}

-(void)nonceCallbackWithMinLength:(uint32_t)minLength
                        maxLength:(uint32_t)maxLength
                            nonce:(void *)nonce
                           nBytes:(uint32_t *)nBytes
{
  // Call the callback if set.
  if (myNonceCb != nil)
  {
    [myNonceCb nonceCallbackWithMinLength:minLength
                                maxLength:maxLength
                                    nonce:nonce
                                   nBytes:nBytes];
    return;
  }

  // Copy to the provided buffer.
  *nBytes = (uint32_t)myNonceBytes;
  memcpy(nonce, myNonce, myNonceBytes);
}

-(uint64_t)timestampCallback
{
  // Call the callback if set.
  if (myTimestampCb != nil)
  {
    return [myTimestampCb timestampCallback];
  }

  // Default to 0 otherwise.
  return 0;
}

-(id)initBase:(mte_drbgs)drbg
     tokBytes:(size_t)tokBytes
    verifiers:(mte_verifiers)verifiers
       cipher:(mte_ciphers)cipher
         hash:(mte_hashes)hash
{
  // Set the options.
  myDrbg = drbg;
  myTokBytes = tokBytes;
  myVerifiers = verifiers;
  myCipher = cipher;
  myHash = hash;

#if defined(__GNUC__) || defined(__clang__)
#  pragma GCC diagnostic push
#  pragma GCC diagnostic ignored "-Wgnu-statement-expression"
#endif
  // The ideal nonce length is the size of the nonce integer, but it must be at
  // least the minimum for the DRBG and no more than the maximum for the DRBG.
  myNonceIntBytes = MAX([MteBase getDrbgsNonceMinBytes:drbg],
                        MIN(sizeof(uint64_t),
                            [MteBase getDrbgsNonceMaxBytes:drbg]));
#if defined(__GNUC__) || defined(__clang__)
#  pragma GCC diagnostic pop
#endif

  // Return ourself.
  return self;
}

@end

mte_status MteBaseEntropyCallback(void *context,
                                  uint32_t min_entropy,
                                  uint32_t min_length,
                                  uint64_t max_length,
                                  uint8_t **entropy_input,
                                  uint64_t *ei_bytes)
{
  MteBase *base = (__bridge MteBase *)context;
  return [base entropyCallbackWithMinEntropy:min_entropy
                                   minLength:min_length
                                   maxLength:max_length
                                entropyInput:entropy_input
                                     eiBytes:ei_bytes];
}

void MteBaseNonceCallback(void *context,
                          uint32_t min_length,
                          uint32_t max_length,
                          void *nonce,
                          uint32_t *n_bytes)
{
  MteBase *base = (__bridge MteBase *)context;
  [base nonceCallbackWithMinLength:min_length
                         maxLength:max_length
                             nonce:nonce
                            nBytes:n_bytes];
}

uint64_t MteBaseTimestampCallback(void *context)
{
  MteBase *base = (__bridge MteBase *)context;
  return [base timestampCallback];
}


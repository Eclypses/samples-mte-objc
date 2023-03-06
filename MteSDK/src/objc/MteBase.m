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
  return MTE_VERSION_MAJOR;
}

+(size_t)getVersionMinor
{
  return MTE_VERSION_MINOR;
}

+(size_t)getVersionPatch
{
  return MTE_VERSION_PATCH;
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
  char *end;
  if (strtoul(mte_base_version(), &end, 10) != MTE_VERSION_MAJOR ||
      strtoul(end + 1, &end, 10) != MTE_VERSION_MINOR ||
      strtoul(end + 1, &end, 10) != MTE_VERSION_PATCH)
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
#if !defined(MTE_BUILD_MINSIZEREL)
  return mte_base_status_count();
#else
  return 0;
#endif
}

+(NSString *)getStatusName:(mte_status)status
{
#if !defined(MTE_BUILD_MINSIZEREL)
  const char *ptr = mte_base_status_name(status);
  NSString *str = ptr == NULL ? nil : [[NSString alloc] initWithUTF8String:ptr];
  return MTE_AUTORELEASE(str);
#else
  (void)status;
  return nil;
#endif
}

+(NSString *)getStatusDescription:(mte_status)status
{
#if !defined(MTE_BUILD_MINSIZEREL)
  const char *ptr = mte_base_status_description(status);
  NSString *str = ptr == NULL ? nil : [[NSString alloc] initWithUTF8String:ptr];
  return MTE_AUTORELEASE(str);
#else
  (void)status;
  return nil;
#endif
}

+(mte_status)getStatusCode:(NSString *)name
{
#if !defined(MTE_BUILD_MINSIZEREL)
  return mte_base_status_code([name UTF8String]);
#else
  (void)name;
  return (mte_status)-1;
#endif
}

+(BOOL)statusIsError:(mte_status)status
{
  return mte_base_status_is_error(status) != MTE_FALSE;
}

+(BOOL)hasRuntimeOpts
{
  return !!MTE_RUNTIME;
}

+(mte_drbgs)getDefaultDrbg
{
  return MTE_DRBG_ENUM;
}

+(size_t)getDefaultTokBytes
{
  return MTE_TOKBYTES;
}

+(mte_verifiers)getDefaultVerifiers
{
  return MTE_VERIFIERS_ENUM;
}

+(mte_ciphers)getDefaultCipher
{
  return MTE_CIPHER_ENUM;
}

+(mte_hashes)getDefaultHash
{
  return MTE_HASH_ENUM;
}

+(size_t)getDrbgsCount
{
#if !defined(MTE_BUILD_MINSIZEREL)
  return mte_base_drbgs_count();
#else
  return 0;
#endif
}

+(NSString *)getDrbgsName:(mte_drbgs)algo
{
#if !defined(MTE_BUILD_MINSIZEREL)
  const char *ptr = mte_base_drbgs_name(algo);
  NSString *str = ptr == NULL ? nil : [[NSString alloc] initWithUTF8String:ptr];
  return MTE_AUTORELEASE(str);
#else
  (void)algo;
  return nil;
#endif
}

+(mte_drbgs)getDrbgsAlgo:(NSString *)name
{
#if !defined(MTE_BUILD_MINSIZEREL)
  return mte_base_drbgs_algo([name UTF8String]);
#else
  (void)name;
  return (mte_drbgs)-1;
#endif
}

+(size_t)getDrbgsSecStrengthBytes:(mte_drbgs)algo
{
#if !defined(MTE_BUILD_MINSIZEREL)
  return mte_base_drbgs_sec_strength_bytes(algo);
#else
  (void)algo;
  return 0;
#endif
}

+(size_t)getDrbgsPersonalMinBytes:(mte_drbgs)algo
{
#if !defined(MTE_BUILD_MINSIZEREL)
  return mte_base_drbgs_personal_min_bytes(algo);
#else
  (void)algo;
  return 0;
#endif
}

+(size_t)getDrbgsPersonalMaxBytes:(mte_drbgs)algo
{
#if !defined(MTE_BUILD_MINSIZEREL)
  return mte_base_drbgs_personal_max_bytes(algo);
#else
  (void)algo;
  return 0;
#endif
}

+(size_t)getDrbgsEntropyMinBytes:(mte_drbgs)algo
{
#if !defined(MTE_BUILD_MINSIZEREL)
  return mte_base_drbgs_entropy_min_bytes(algo);
#else
  (void)algo;
  return 0;
#endif
}

+(size_t)getDrbgsEntropyMaxBytes:(mte_drbgs)algo
{
#if !defined(MTE_BUILD_MINSIZEREL)
  return mte_base_drbgs_entropy_max_bytes(algo);
#else
  (void)algo;
  return 0;
#endif
}

+(size_t)getDrbgsNonceMinBytes:(mte_drbgs)algo
{
#if !defined(MTE_BUILD_MINSIZEREL)
  return mte_base_drbgs_nonce_min_bytes(algo);
#else
  (void)algo;
  return 0;
#endif
}

+(size_t)getDrbgsNonceMaxBytes:(mte_drbgs)algo
{
#if !defined(MTE_BUILD_MINSIZEREL)
  return mte_base_drbgs_nonce_max_bytes(algo);
#else
  (void)algo;
  return 0;
#endif
}

+(uint64_t)getDrbgsReseedInterval:(mte_drbgs)algo
{
#if !defined(MTE_BUILD_MINSIZEREL)
  return mte_base_drbgs_reseed_interval(algo);
#else
  (void)algo;
  return 0;
#endif
}

+(void)setIncrInstError:(BOOL)flag
{
#if !defined(MTE_BUILD_MINSIZEREL)
  mte_base_drbgs_incr_inst_error(flag ? MTE_TRUE : MTE_FALSE);
#else
  (void)flag;
#endif
}

+(void)setIncrGenError:(BOOL)flag after:(size_t)after
{
#if !defined(MTE_BUILD_MINSIZEREL)
  mte_base_drbgs_incr_gen_error(flag ? MTE_TRUE : MTE_FALSE, after);
#else
  (void)flag;
  (void)after;
#endif
}

+(size_t)getVerifiersCount
{
#if !defined(MTE_BUILD_MINSIZEREL)
  return mte_base_verifiers_count();
#else
  return 0;
#endif
}

+(NSString *)getVerifiersName:(mte_verifiers)algo
{
#if !defined(MTE_BUILD_MINSIZEREL)
  const char *ptr = mte_base_verifiers_name(algo);
  NSString *str = ptr == NULL ? nil : [[NSString alloc] initWithUTF8String:ptr];
  return MTE_AUTORELEASE(str);
#else
  (void)algo;
  return nil;
#endif
}

+(mte_verifiers)getVerifiersAlgo:(NSString *)name
{
#if !defined(MTE_BUILD_MINSIZEREL)
  return mte_base_verifiers_algo([name UTF8String]);
#else
  (void)name;
  return (mte_verifiers)-1;
#endif
}

+(size_t)getCiphersCount
{
#if !defined(MTE_BUILD_MINSIZEREL)
  return mte_base_ciphers_count();
#else
  return 0;
#endif
}

+(NSString *)getCiphersName:(mte_ciphers)algo
{
#if !defined(MTE_BUILD_MINSIZEREL)
  const char *ptr = mte_base_ciphers_name(algo);
  NSString *str = ptr == NULL ? nil : [[NSString alloc] initWithUTF8String:ptr];
  return MTE_AUTORELEASE(str);
#else
  (void)algo;
  return nil;
#endif
}

+(mte_ciphers)getCiphersAlgo:(NSString *)name
{
#if !defined(MTE_BUILD_MINSIZEREL)
  return mte_base_ciphers_algo([name UTF8String]);
#else
  (void)name;
  return (mte_ciphers)-1;
#endif
}

+(size_t)getCiphersBlockBytes:(mte_ciphers)algo
{
#if !defined(MTE_BUILD_MINSIZEREL)
  return mte_base_ciphers_block_bytes(algo);
#else
  (void)algo;
  return 0;
#endif
}

+(size_t)getHashesCount
{
#if !defined(MTE_BUILD_MINSIZEREL)
  return mte_base_hashes_count();
#else
  return 0;
#endif
}

+(NSString *)getHashesName:(mte_hashes)algo
{
#if !defined(MTE_BUILD_MINSIZEREL)
  const char *ptr = mte_base_hashes_name(algo);
  NSString *str = ptr == NULL ? nil : [[NSString alloc] initWithUTF8String:ptr];
  return MTE_AUTORELEASE(str);
#else
  (void)algo;
  return nil;
#endif
}

+(mte_hashes)getHashesAlgo:(NSString *)name
{
#if !defined(MTE_BUILD_MINSIZEREL)
  return mte_base_hashes_algo([name UTF8String]);
#else
  (void)name;
  return (mte_hashes)-1;
#endif
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

-(mte_status)entropyCallback:(mte_drbg_ei_info *)info
{
  // Call the callback if set.
  if (myEntropyCb != nil)
  {
    return [myEntropyCb entropyCallback:info];
  }

  // Check the length.
  if (myEntropyInputBytes < info->min_length ||
      myEntropyInputBytes > info->max_length)
  {
    return mte_status_drbg_catastrophic;
  }

  // Just point at the entropy buffer.
  info->buff = myEntropyInput;

  // Success.
  info->bytes = (MTE_SIZE_T)myEntropyInputBytes;
  return mte_status_success;
}

-(void)nonceCallback:(mte_drbg_nonce_info *)info
{
  // Call the callback if set.
  if (myNonceCb != nil)
  {
    [myNonceCb nonceCallback:info];
    return;
  }

  // Copy to the provided buffer.
  info->bytes = (MTE_SIZE8_T)myNonceBytes;
  memcpy(info->buff, myNonce, myNonceBytes);
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

mte_status MteBaseEntropyCallback(void *context, mte_drbg_ei_info *info)
{
  MteBase *base = (__bridge MteBase *)context;
  return [base entropyCallback:info];
}

void MteBaseNonceCallback(void *context, mte_drbg_nonce_info *info)
{
  MteBase *base = (__bridge MteBase *)context;
  [base nonceCallback:info];
}

MTE_UINT64_T MteBaseTimestampCallback(void *context)
{
  MteBase *base = (__bridge MteBase *)context;
  return [base timestampCallback];
}


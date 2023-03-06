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
#define NS_SUPPRESS_MIN_MAX_ABS
#import "MteDec.h"
#import "mte_dec.h"

@implementation MteDec

-(id)init
{
  return [self initWithTWindow:0 sWindow:0];
}

-(id)initWithTWindow:(uint64_t)tWindow sWindow:(int32_t)sWindow
{
  return [self initWithDrbg:MTE_DRBG_ENUM
                   tokBytes:MTE_TOKBYTES
                  verifiers:MTE_VERIFIERS_ENUM
                    tWindow:tWindow
                    sWindow:sWindow];
}

-(id)initWithDrbg:(mte_drbgs)drbg
         tokBytes:(size_t)tokBytes
        verifiers:(mte_verifiers)verifiers
          tWindow:(uint64_t)tWindow
          sWindow:(int32_t)sWindow
{
  // Initialize the base.
  self = [super initBase:drbg
                tokBytes:tokBytes
               verifiers:verifiers
                  cipher:mte_ciphers_none
                    hash:mte_hashes_none];

  // Set up the decode arguments.
  MTE_SET_TIMESTAMP_CB(myDecArgs,
                       &MteBaseTimestampCallback, (__bridge void *)self);

  // Get the decoder size.
  const mte_dec_init_info info = MTE_DEC_INIT_INFO_INIT(
    drbg, (MTE_SIZE8_T)tokBytes, verifiers, tWindow, sWindow, NULL, NULL);
  size_t bytes = mte_dec_state_bytes(&info);
  if (bytes == 0)
  {
    [NSException raise:NSInvalidArgumentException
                format:@"MteDec initWithDrbg: Invalid options."];
  }

  // Initialize the decoder state.
  myDecoder = malloc(bytes);
  mte_status status = mte_dec_state_init(myDecoder, &info);
  if (status != mte_status_success)
  {
    [NSException raise:NSInvalidArgumentException
                format:@"MteDec initWithDrbg: Invalid options."];
  }

  // Allocate the save buffer to hold the larger version. Set the save size to
  // the raw version length.
  mySaveBytes = mte_dec_save_bytes(myDecoder);
#if !defined(MTE_BUILD_MINSIZEREL)
  bytes = mte_dec_save_bytes_b64(myDecoder);
  bytes = mySaveBytes < bytes ? bytes : mySaveBytes;
  mySaveBuff = malloc(bytes);
#else
  mySaveBuff = malloc(mySaveBytes);
#endif

  // Return ourself.
  return self;
}

-(void)dealloc
{
  // Uninstantiate if constructed fully.
  if (myDecoder != nil)
  {
    [self uninstantiate];
  }

  // Free the buffers.
  free(myDecoder);
  free(myDecBuff);
  free(mySaveBuff);

  // Super.
  MTE_SUP_DEALLOC();
}

-(mte_status)instantiate:(const void *)ps bytes:(size_t)psBytes
{
  const mte_drbg_inst_info info =
  {
    &MteBaseEntropyCallback, (__bridge void *)self,
    &MteBaseNonceCallback, (__bridge void *)self,
    ps, (MTE_SIZE_T)psBytes
  };
  return mte_dec_instantiate(myDecoder, &info);
}

-(mte_status)instantiate:(NSString *)ps
{
  const char *utf8 = [ps UTF8String];
  return [self instantiate:utf8 bytes:strlen(utf8)];
}

-(uint64_t)getReseedCounter
{
  return mte_dec_reseed_counter(myDecoder);
}

-(const void *)saveState:(size_t *)stateBytes
{
  // Save the state, set the length, and return the buffer.
  mte_status status = mte_dec_state_save(myDecoder, mySaveBuff);
  *stateBytes = status == mte_status_success ? mySaveBytes : 0;
  return status == mte_status_success ? mySaveBuff : nil;
}

-(NSString *)saveStateB64
{
#if !defined(MTE_BUILD_MINSIZEREL)
  mte_status status = mte_dec_state_save_b64(myDecoder, mySaveBuff);
  return status == mte_status_success ?
    MTE_AUTORELEASE([[NSString alloc] initWithUTF8String:mySaveBuff]) : nil;
#else
  return nil;
#endif
}

-(mte_status)restoreState:(const void *)saved
{
  return mte_dec_state_restore(myDecoder, saved);
}

-(mte_status)restoreStateB64:(NSString *)saved
{
#if !defined(MTE_BUILD_MINSIZEREL)
  return mte_dec_state_restore_b64(myDecoder, [saved UTF8String]);
#else
  (void)saved;
  return mte_status_unsupported;
#endif
}

-(size_t)getBuffBytes:(size_t)encodedBytes
{
  return mte_dec_buff_bytes(myDecoder, encodedBytes);
}

-(size_t)getBuffBytesB64:(size_t)encodedBytes
{
#if !defined(MTE_BUILD_MINSIZEREL)
  return mte_dec_buff_bytes_b64(myDecoder, encodedBytes);
#else
  (void)encodedBytes;
  return 0;
#endif
}

-(void *)decode:(const void *)encoded
   encodedBytes:(size_t)encodedBytes
   decodedBytes:(size_t *)decodedBytes
         status:(mte_status *)status
{
  // Get the decode buffer requirement and reallocate if necessary.
  size_t buffBytes = mte_dec_buff_bytes(myDecoder, encodedBytes);
  if (buffBytes > myDecBuffBytes)
  {
    free(myDecBuff);
    myDecBuff = malloc(buffBytes);
    myDecBuffBytes = buffBytes;
  }

  // Decode.
  size_t dOff = 0;
  *status = [self decode:encoded
                  encOff:0
                encBytes:encodedBytes
                 decoded:myDecBuff
                  decOff:&dOff
                decBytes:decodedBytes];

  // Return the decoded version.
  return myDecBuff + dOff;
}

-(void *)decodeB64:(NSString *)encoded
      decodedBytes:(size_t *)decodedBytes
            status:(mte_status *)status
{
#if !defined(MTE_BUILD_MINSIZEREL)
  // Get the Base64-encoded length.
  const char *enc8 = [encoded UTF8String];
  size_t encBytes = strlen(enc8);

  // Get the decode buffer requirement and reallocate if necessary.
  size_t buffBytes = mte_dec_buff_bytes_b64(myDecoder, encBytes);
  if (buffBytes > myDecBuffBytes)
  {
    free(myDecBuff);
    myDecBuff = malloc(buffBytes);
    myDecBuffBytes = buffBytes;
  }

  // Decode.
  size_t dOff = 0;
  *status = [self decodeB64:enc8
                     encOff:0
                   encBytes:encBytes
                    decoded:myDecBuff
                     decOff:&dOff
                   decBytes:decodedBytes];

  // Return the decoded version.
  return myDecBuff + dOff;
#else
  (void)encoded;
  (void)decodedBytes;
  (void)status;
  return nil;
#endif
}

-(NSString *)decode:(const void *)encoded
       encodedBytes:(size_t)encodedBytes
             status:(mte_status *)status
{
  // Decode.
  size_t dBytes;
  const char *decoded = (const char *)[self decode:encoded
                                      encodedBytes:encodedBytes
                                      decodedBytes:&dBytes
                                            status:status];
  if ([MteBase statusIsError:*status])
  {
    return nil;
  }

  // Assign the result to a string and return it.
  NSString *str = [[NSString alloc] initWithUTF8String:decoded];
  return MTE_AUTORELEASE(str);
}

-(NSString *)decodeB64:(NSString *)encoded
                status:(mte_status *)status
{
  // Decode.
  size_t dBytes;
  const char *decoded = (const char *)[self decodeB64:encoded
                                         decodedBytes:&dBytes
                                               status:status];
  if ([MteBase statusIsError:*status])
  {
    return nil;
  }

  // Assign the result to a string and return it.
  NSString *str = [[NSString alloc] initWithUTF8String:decoded];
  return MTE_AUTORELEASE(str);
}

-(mte_status)decode:(const void *)encoded
             encOff:(size_t)encOff
           encBytes:(size_t)encBytes
            decoded:(void *)decoded
             decOff:(size_t *)decOff
           decBytes:(size_t *)decBytes
{
  // Decode.
  MTE_SET_DEC_IO(myDecArgs,
                 (const uint8_t *)encoded + encOff,
                 (MTE_SIZE_T)encBytes,
                 (uint8_t *)decoded + *decOff);
  mte_status status = mte_dec_decode(myDecoder, &myDecArgs);
  *decOff = (uint8_t *)myDecArgs.decoded - (uint8_t *)decoded;
  *decBytes = myDecArgs.bytes;

  // Return status.
  return status;
}

-(mte_status)decodeB64:(const void *)encoded
                encOff:(size_t)encOff
              encBytes:(size_t)encBytes
               decoded:(void *)decoded
                decOff:(size_t *)decOff
              decBytes:(size_t *)decBytes
{
#if !defined(MTE_BUILD_MINSIZEREL)
  // Decode.
  MTE_SET_DEC_IO(myDecArgs,
                 (const uint8_t *)encoded + encOff,
                 (MTE_SIZE_T)encBytes,
                 (uint8_t *)decoded + *decOff);
  mte_status status = mte_dec_decode_b64(myDecoder, &myDecArgs);
  *decOff = (uint8_t *)myDecArgs.decoded - (uint8_t *)decoded;
  *decBytes = myDecArgs.bytes;

  // Return status.
  return status;
#else
  (void)encoded;
  (void)encOff;
  (void)encBytes;
  (void)decoded;
  (void)decOff;
  (void)decBytes;
  return mte_status_unsupported;
#endif
}

-(uint64_t)getEncTs
{
  return MTE_GET_ENC_TS(myDecArgs);
}

-(uint64_t)getDecTs
{
  return MTE_GET_DEC_TS(myDecArgs);
}

-(uint32_t)getMsgSkipped
{
  return MTE_GET_MSG_SKIPPED(myDecArgs);
}

-(mte_status)uninstantiate
{
  return mte_dec_uninstantiate(myDecoder);
}

@end


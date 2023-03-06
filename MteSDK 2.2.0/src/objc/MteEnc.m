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
#import "MteEnc.h"
#import "mte_enc.h"

@implementation MteEnc

-(id)init
{
  BOOL bt = [MteBase hasBuildtimeOpts];
  return [self initWithDrbg:bt ? [MteBase getBuildtimeDrbg] :
                                 MTE_BASE_DEFAULT_DRBG
                   tokBytes:bt ? [MteBase getBuildtimeTokBytes] :
                                 MTE_BASE_DEFAULT_TOKBYTES
                  verifiers:bt ? [MteBase getBuildtimeVerifiers] :
                                 MTE_BASE_DEFAULT_VERIFIERS];
}

-(id)initWithDrbg:(mte_drbgs)drbg
         tokBytes:(size_t)tokBytes
        verifiers:(mte_verifiers)verifiers
{
  // Initialize the base.
  self = [super initBase:drbg
                tokBytes:tokBytes
               verifiers:verifiers
                  cipher:mte_ciphers_none
                    hash:mte_hashes_none];

  // Get the encoder size.
  size_t bytes = mte_enc_state_bytes(drbg, (uint32_t)tokBytes, verifiers);
  if (bytes == 0)
  {
    [NSException raise:NSInvalidArgumentException
                format:@"MteEnc initWithDrbg: Invalid options."];
  }

  // Initialize the encoder state.
  myEncoder = malloc(bytes);
  mte_status status =
    mte_enc_state_init(myEncoder, drbg, (uint32_t)tokBytes, verifiers);
  if (status != mte_status_success)
  {
    [NSException raise:NSInvalidArgumentException
                format:@"MteEnc initWithDrbg: Invalid options."];
  }

  // Allocate the save buffer to hold the larger Base64 version. Set the save
  // size to the raw version length.
  mySaveBuff = malloc(mte_enc_save_bytes_b64(myEncoder));
  mySaveBytes = mte_enc_save_bytes(myEncoder);

  // Return ourself.
  return self;
}

-(void)dealloc
{
  // Uninstantiate.
  [self uninstantiate];

  // Free the buffers.
  free(myEncoder);
  free(myEncBuff);
  free(mySaveBuff);

  // Super.
  MTE_SUP_DEALLOC();
}

-(mte_status)instantiate:(const void *)ps bytes:(size_t)psBytes
{
  return mte_enc_instantiate(myEncoder,
                             &MteBaseEntropyCallback, (__bridge void *)self,
                             &MteBaseNonceCallback, (__bridge void *)self,
                             ps, (uint32_t)psBytes);
}

-(mte_status)instantiate:(NSString *)ps
{
  const char *utf8 = [ps UTF8String];
  return [self instantiate:utf8 bytes:strlen(utf8)];
}

-(uint64_t)getReseedCounter
{
  return mte_enc_reseed_counter(myEncoder);
}

-(const void *)saveState:(size_t *)stateBytes
{
  // Save the state, set the length, and return the buffer.
  mte_status status = mte_enc_state_save(myEncoder, mySaveBuff);
  *stateBytes = status == mte_status_success ? mySaveBytes : 0;
  return status == mte_status_success ? mySaveBuff : nil;
}

-(NSString *)saveStateB64
{
  mte_status status = mte_enc_state_save_b64(myEncoder, mySaveBuff);
  return status == mte_status_success ?
    MTE_AUTORELEASE([[NSString alloc] initWithUTF8String:mySaveBuff]) : nil;
}

-(mte_status)restoreState:(const void *)saved
{
  return mte_enc_state_restore(myEncoder, saved);
}

-(mte_status)restoreStateB64:(NSString *)saved
{
  return mte_enc_state_restore_b64(myEncoder, [saved UTF8String]);
}

-(size_t)getBuffBytes:(size_t)dataBytes
{
  return mte_enc_buff_bytes(myEncoder, (uint32_t)dataBytes);
}

-(size_t)getBuffBytesB64:(size_t)dataBytes
{
  return mte_enc_buff_bytes_b64(myEncoder, (uint32_t)dataBytes);
}

-(const void *)encode:(const void *)data
            dataBytes:(size_t)dataBytes
         encodedBytes:(size_t *)encodedBytes
               status:(mte_status *)status
{
  // Get the encode buffer requirement and reallocate if necessary.
  size_t buffBytes = mte_enc_buff_bytes(myEncoder, (uint32_t)dataBytes);
  if (buffBytes > myEncBuffBytes)
  {
    free(myEncBuff);
    myEncBuff = malloc(buffBytes);
    myEncBuffBytes = buffBytes;
  }

  // Encode.
  size_t eOff = 0;
  *status = [self encode:data
                 dataOff:0
               dataBytes:dataBytes
                 encoded:myEncBuff
                  encOff:&eOff
                encBytes:encodedBytes];

  // Return the encoded version.
  return myEncBuff + eOff;
}

-(NSString *)encodeB64:(const void *)data
             dataBytes:(size_t)dataBytes
                status:(mte_status *)status
{
  // Get the encode buffer requirement and reallocate if necessary.
  size_t buffBytes = mte_enc_buff_bytes_b64(myEncoder, (uint32_t)dataBytes);
  if (buffBytes > myEncBuffBytes)
  {
    free(myEncBuff);
    myEncBuff = malloc(buffBytes);
    myEncBuffBytes = buffBytes;
  }

  // Encode.
  size_t eOff = 0;
  size_t eBytes;
  *status = [self encodeB64:data
                    dataOff:0
                  dataBytes:dataBytes
                    encoded:myEncBuff
                     encOff:&eOff
                   encBytes:&eBytes];
  if (*status != mte_status_success)
  {
    return nil;
  }

  // Return the encoded version.
  NSString *str = [[NSString alloc] initWithUTF8String:myEncBuff + eOff];
  return MTE_AUTORELEASE(str);
}

-(const void *)encode:(NSString *)str
         encodedBytes:(size_t *)encodedBytes
               status:(mte_status *)status
{
  const char *utf8 = [str UTF8String];
  size_t bytes = strlen(utf8);
  return
    [self encode:utf8 dataBytes:bytes encodedBytes:encodedBytes status:status];
}

-(NSString *)encodeB64:(NSString *)str
                status:(mte_status *)status
{
  const char *utf8 = [str UTF8String];
  size_t bytes = strlen(utf8);
  return [self encodeB64:utf8 dataBytes:bytes status:status];
}

-(mte_status)encode:(const void *)data
            dataOff:(size_t)dataOff
          dataBytes:(size_t)dataBytes
            encoded:(void *)encoded
             encOff:(size_t *)encOff
           encBytes:(size_t *)encBytes
{
  // Encode.
  uint32_t eOff;
  uint32_t eBytes;
  mte_status status =
    mte_enc_encode(myEncoder,
                   &MteBaseTimestampCallback, (__bridge void *)self,
                   (const uint8_t *)data + dataOff,
                   (uint32_t)dataBytes,
                   (uint8_t *)encoded + *encOff,
                   &eOff, &eBytes);
  *encOff += eOff;
  *encBytes = eBytes;

  // Return status.
  return status;
}

-(mte_status)encodeB64:(const void *)data
               dataOff:(size_t)dataOff
             dataBytes:(size_t)dataBytes
               encoded:(void *)encoded
                encOff:(size_t *)encOff
              encBytes:(size_t *)encBytes
{
  // Encode.
  uint32_t eOff;
  uint32_t eBytes;
  mte_status status =
    mte_enc_encode_b64(myEncoder,
                       &MteBaseTimestampCallback, (__bridge void *)self,
                       (const uint8_t *)data + dataOff,
                       (uint32_t)dataBytes,
                       (uint8_t *)encoded + *encOff,
                       &eOff, &eBytes);
  *encOff += eOff;
  *encBytes = eBytes;

  // Return status.
  return status;
}

-(mte_status)uninstantiate
{
  return mte_enc_uninstantiate(myEncoder);
}

@end


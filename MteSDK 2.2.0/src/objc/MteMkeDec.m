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
#import "MteMkeDec.h"
#import "mte_mke_dec.h"

@implementation MteMkeDec

-(id)init
{
  return [self initWithTWindow:0 sWindow:0];
}

-(id)initWithTWindow:(uint64_t)tWindow sWindow:(int32_t)sWindow
{
  BOOL bt = [MteBase hasBuildtimeOpts];
  return [self initWithDrbg:bt ? [MteBase getBuildtimeDrbg] :
                                 MTE_BASE_DEFAULT_DRBG
                   tokBytes:bt ? [MteBase getBuildtimeTokBytes] :
                                 MTE_BASE_DEFAULT_TOKBYTES
                  verifiers:bt ? [MteBase getBuildtimeVerifiers] :
                                 MTE_BASE_DEFAULT_VERIFIERS
                     cipher:bt ? [MteBase getBuildtimeCipher] :
                                 MTE_BASE_DEFAULT_CIPHER
                       hash:bt ? [MteBase getBuildtimeHash] :
                                 MTE_BASE_DEFAULT_HASH
                    tWindow:tWindow
                    sWindow:sWindow];
}

-(id)initWithDrbg:(mte_drbgs)drbg
         tokBytes:(size_t)tokBytes
        verifiers:(mte_verifiers)verifiers
           cipher:(mte_ciphers)cipher
             hash:(mte_hashes)hash
          tWindow:(uint64_t)tWindow
          sWindow:(int32_t)sWindow
{
  // Initialize the base.
  self = [super initBase:drbg
                tokBytes:tokBytes
               verifiers:verifiers
                  cipher:cipher
                    hash:hash];

  // Get the decoder size.
  size_t bytes = mte_mke_dec_state_bytes(drbg,
                                         (uint32_t)tokBytes,
                                         verifiers,
                                         cipher,
                                         hash);
  if (bytes == 0)
  {
    [NSException raise:NSInvalidArgumentException
                format:@"MteMkeDec initWithDrbg: Invalid options."];
  }

  // Initialize the decoder state.
  myDecoder = malloc(bytes);
  mte_status status = mte_mke_dec_state_init(myDecoder,
                                             drbg,
                                             (uint32_t)tokBytes,
                                             verifiers,
                                             cipher,
                                             hash,
                                             tWindow,
                                             sWindow);
  if (status != mte_status_success)
  {
    [NSException raise:NSInvalidArgumentException
                format:@"MteMkeDec initWithDrbg: Invalid options."];
  }

  // Allocate the save buffer to hold the larger Base64 version. Set the save
  // size to the raw version length.
  mySaveBuff = malloc(mte_mke_dec_save_bytes_b64(myDecoder));
  mySaveBytes = mte_mke_dec_save_bytes(myDecoder);

  // Allocate the decryptor state.
  myDecryptor = malloc(mte_mke_dec_decrypt_state_bytes(myDecoder));
  myCiphBlockBytes = mte_base_ciphers_block_bytes(cipher);

  // Return ourself.
  return self;
}

-(void)dealloc
{
  // Uninstantiate.
  [self uninstantiate];

  // Free the buffers.
  free(myDecoder);
  free(myDecBuff);
  free(mySaveBuff);

  // Super.
  MTE_SUP_DEALLOC();
}

-(mte_status)instantiate:(const void *)ps bytes:(size_t)psBytes
{
  return mte_mke_dec_instantiate(myDecoder,
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
  return mte_mke_dec_reseed_counter(myDecoder);
}

-(const void *)saveState:(size_t *)stateBytes
{
  // Save the state, set the length, and return the buffer.
  mte_status status = mte_mke_dec_state_save(myDecoder, mySaveBuff);
  *stateBytes = status == mte_status_success ? mySaveBytes : 0;
  return status == mte_status_success ? mySaveBuff : nil;
}

-(NSString *)saveStateB64
{
  mte_status status = mte_mke_dec_state_save_b64(myDecoder, mySaveBuff);
  return status == mte_status_success ?
    MTE_AUTORELEASE([[NSString alloc] initWithUTF8String:mySaveBuff]) : nil;
}

-(mte_status)restoreState:(const void *)saved
{
  return mte_mke_dec_state_restore(myDecoder, saved);
}

-(mte_status)restoreStateB64:(NSString *)saved
{
  return mte_mke_dec_state_restore_b64(myDecoder, [saved UTF8String]);
}

-(size_t)getBuffBytes:(size_t)encodedBytes
{
  return mte_mke_dec_buff_bytes(myDecoder, (uint32_t)encodedBytes);
}

-(size_t)getBuffBytesB64:(size_t)encodedBytes
{
  return mte_mke_dec_buff_bytes_b64(myDecoder, (uint32_t)encodedBytes);
}

-(void *)decode:(const void *)encoded
   encodedBytes:(size_t)encodedBytes
   decodedBytes:(size_t *)decodedBytes
         status:(mte_status *)status
{
  // Get the decode buffer requirement and reallocate if necessary.
  size_t buffBytes = mte_mke_dec_buff_bytes(myDecoder, (uint32_t)encodedBytes);
  if (buffBytes > myDecBuffBytes)
  {
    free(myDecBuff);
    myDecBuff = malloc(buffBytes);
    myDecBuffBytes = buffBytes;
  }
  else if (buffBytes == 0)
  {
    *status = mte_status_invalid_input;
    return nil;
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
  // Get the Base64-encoded length.
  const char *enc8 = [encoded UTF8String];
  uint32_t encBytes = (uint32_t)strlen(enc8);

  // Get the decode buffer requirement and reallocate if necessary.
  size_t buffBytes = mte_mke_dec_buff_bytes_b64(myDecoder, (uint32_t)encBytes);
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
  uint32_t dOff;
  uint32_t dBytes;
  mte_status status =
    mte_mke_dec_decode(myDecoder,
                       &MteBaseTimestampCallback, (__bridge void *)self,
                       (const uint8_t *)encoded + encOff,
                       (uint32_t)encBytes,
                       (uint8_t *)decoded + *decOff,
                       &dOff, &dBytes);
  *decOff += dOff;
  *decBytes = dBytes;

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
  // Decode.
  uint32_t dOff;
  uint32_t dBytes;
  mte_status status =
    mte_mke_dec_decode_b64(myDecoder,
                           &MteBaseTimestampCallback, (__bridge void *)self,
                           (const uint8_t *)encoded + encOff,
                           (uint32_t)encBytes,
                           (uint8_t *)decoded + *decOff,
                           &dOff, &dBytes);
  *decOff += dOff;
  *decBytes = dBytes;

  // Return status.
  return status;
}

-(mte_status)startDecrypt
{
  return mte_mke_dec_decrypt_start(myDecoder, myDecryptor);
}

-(const void *)decryptChunk:(const void *)encrypted
             encryptedBytes:(size_t)encryptedBytes
             decryptedBytes:(size_t *)decryptedBytes
{
  // Reallocate the decoder buffer if necessary.
  size_t buffBytes = encryptedBytes + myCiphBlockBytes;
  if (buffBytes > myDecBuffBytes)
  {
    free(myDecBuff);
    myDecBuff = malloc(buffBytes);
    myDecBuffBytes = buffBytes;
  }

  // Decrypt and return the decrypted.
  uint32_t dBytes;
  mte_status status = mte_mke_dec_decrypt_chunk(myDecoder, myDecryptor,
                                                encrypted,
                                                (uint32_t)encryptedBytes,
                                                myDecBuff,
                                                &dBytes);
  *decryptedBytes = dBytes;
  return status == mte_status_success ? myDecBuff : nil;
}

-(size_t)decryptChunk:(const void *)encrypted
               encOff:(size_t)encOff
             encBytes:(size_t)encBytes
            decrypted:(void *)decrypted
               decOff:(size_t)decOff
{
  // Decrypt and return the amount decrypted.
  uint32_t dBytes;
  mte_status status =
    mte_mke_dec_decrypt_chunk(myDecoder, myDecryptor,
                              (const uint8_t *)encrypted + encOff,
                              (uint32_t)encBytes,
                              (uint8_t *)decrypted + decOff,
                              &dBytes);
  return status == mte_status_success ? dBytes : ULONG_MAX;
}

-(const void *)finishDecrypt:(size_t *)decryptedBytes
                      status:(mte_status *)status
{
  uint32_t dOff;
  uint32_t dBytes;
  *status =
    mte_mke_dec_decrypt_finish(myDecoder, myDecryptor,
                               &MteBaseTimestampCallback, (__bridge void *)self,
                               &dOff, &dBytes);
  *decryptedBytes = dBytes;
  return myDecryptor + dOff;
}

-(uint64_t)getEncTs
{
  return mte_mke_dec_enc_ts(myDecoder);
}

-(uint64_t)getDecTs
{
  return mte_mke_dec_dec_ts(myDecoder);
}

-(uint32_t)getMsgSkipped
{
  return mte_mke_dec_msg_skipped(myDecoder);
}

-(mte_status)uninstantiate
{
  return mte_mke_dec_uninstantiate(myDecoder);
}

@end


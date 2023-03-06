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

// Class MteDec
//
// This is the MTE decoder.
//
// To use, alloc and initWithDrbg:, send instantiate:, send decode: zero or
// more times to decode each encoded data, then optionally send uninstantiate:
// to clear the random state.
//
// Alternatively, the state can be saved any time after instantiate: and
// restored instead of instantiate: to pick up at a known point.
@interface MteDec : MteBase
{
  // The decoder state.
  uint8_t *myDecoder;

  // Decoder buffer.
  char *myDecBuff;
  size_t myDecBuffBytes;
  mte_dec_args myDecArgs;

  // State save buffer.
  char *mySaveBuff;
  size_t mySaveBytes;
}

// Initialize using default options defined in mte_settings.h.
//
// The timestamp window and sequence window are set to 0.
-(id)init;

// Initialize using default options defined in mte_settings.h.
//
// The timestamp window and sequence window must still be provided.
-(id)initWithTWindow:(uint64_t)tWindow sWindow:(int32_t)sWindow;

// Initialize taking the DRBG, token size in bytes, verifiers algorithm,
// timestamp window, and sequence window.
-(id)initWithDrbg:(mte_drbgs)drbg
         tokBytes:(size_t)tokBytes
        verifiers:(mte_verifiers)verifiers
          tWindow:(uint64_t)tWindow
          sWindow:(int32_t)sWindow;

// Deallocate. The -uninstantiate: message is sent.
-(void)dealloc;

// Instantiate the decoder with the personalization string. The entropy and
// nonce callbacks will be called to get the rest of the seeding material.
// Returns the status.
-(mte_status)instantiate:(const void *)ps bytes:(size_t)psBytes;
-(mte_status)instantiate:(NSString *)ps;

// Returns the reseed counter.
-(uint64_t)getReseedCounter;

// Returns the saved state and sets *stateBytes to the length of the saved
// state in bytes. The Base64 version returns a null-terminated Base64-encoded
// saved state instead. On error, nil is returned and *stateBytes is set to
// 0.
-(const void *)saveState:(size_t *)stateBytes;
-(NSString *)saveStateB64;

// Restore a saved state, which must be the same length as was returned from
// the saveState: call. The Base64 version takes a Base64-encoded saved state
// as produced by saveStateB64:. Returns the status.
-(mte_status)restoreState:(const void *)saved;
-(mte_status)restoreStateB64:(NSString *)saved;

// Returns the decode buffer size in bytes given the encoded length in bytes.
-(size_t)getBuffBytes:(size_t)encodedBytes;
-(size_t)getBuffBytesB64:(size_t)encodedBytes;

// Decodes the given encoded version of the given length in bytes. Returns the
// decoded data and sets *decodedBytes to the length of the decoded data in
// bytes and *status to the status.
-(void *)decode:(const void *)encoded
   encodedBytes:(size_t)encodedBytes
   decodedBytes:(size_t *)decodedBytes
         status:(mte_status *)status;
-(void *)decodeB64:(NSString *)encoded
      decodedBytes:(size_t *)decodedBytes
            status:(mte_status *)status;

// Decode the given encoded version to a string. Returns the string and sets
// *status to the status.
-(NSString *)decode:(const void *)encoded
       encodedBytes:(size_t)encodedBytes
             status:(mte_status *)status;
-(NSString *)decodeB64:(NSString *)encoded
                status:(mte_status *)status;

// Decode the given encoded version of the given length at the given offset to
// the given buffer at the given offset. Returns the status. Sets decOff to
// the offset of the decoded version. Sets decBytes to the decoded length in
// bytes. The decoded buffer must have sufficient length remaining after
// the offset. Use getBuffBytes() or getBuffBytes64() to determine the
// buffer requirement for raw or Base64 respectively.
-(mte_status)decode:(const void *)encoded
             encOff:(size_t)encOff
           encBytes:(size_t)encBytes
            decoded:(void *)decoded
             decOff:(size_t *)decOff
           decBytes:(size_t *)decBytes;
-(mte_status)decodeB64:(const void *)encoded
                encOff:(size_t)encOff
              encBytes:(size_t)encBytes
               decoded:(void *)decoded
                decOff:(size_t *)decOff
              decBytes:(size_t *)decBytes;

// Returns the timestamp set during encoding or 0 if there is no timestamp.
-(uint64_t)getEncTs;

// Returns the timestamp set during decoding or 0 if there is no timestamp.
-(uint64_t)getDecTs;

// Returns the number of messages that were skipped to get in sync during the
// decode or 0 if there is no sequencing.
-(uint32_t)getMsgSkipped;

// Uninstantiate the receiver. It is no longer usable after this call. Returns
// the MTE status.
-(mte_status)uninstantiate;

@end


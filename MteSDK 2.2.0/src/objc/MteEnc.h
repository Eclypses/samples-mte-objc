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

// Class MteEnc
//
// This is the MTE encoder.
//
// To use, alloc and initWithDrbg:, call instantiate:, call encode: zero or
// more times to encode each piece of data, then optionally call uninstantiate:
// to clear the random state.
//
// Alternatively, the state can be saved any time after instantiate: and
// restored instead of instantiate: to pick up at a known point.
@interface MteEnc : MteBase
{
  // The encoder state.
  uint8_t *myEncoder;

  // Encoder buffer.
  char *myEncBuff;
  size_t myEncBuffBytes;

  // State save buffer.
  char *mySaveBuff;
  size_t mySaveBytes;
}

// Initialize using default options. If the library has buildtime options,
// they are used; otherwise, the options chosen are defined by the
// MTE_BASE_DEFAULT_* constants.
-(id)init;

// Initialize taking the DRBG, token size in bytes, and verifiers algorithm.
-(id)initWithDrbg:(mte_drbgs)drbg
         tokBytes:(size_t)tokBytes
        verifiers:(mte_verifiers)verifiers;

// Deallocate. The uninstantiate: method is called.
-(void)dealloc;

// Instantiate the encoder with the personalization string. The entropy and
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

// Returns the encode buffer size in bytes given the data length in bytes.
-(size_t)getBuffBytes:(size_t)dataBytes;
-(size_t)getBuffBytesB64:(size_t)dataBytes;

// Encode the given data of the given length in bytes. Returns the encoded
// version and sets *encodedBytes to the length of the encoded version in bytes
// and *status to the status. The Base64 version returns a Base64-encoded string
// instead.
-(const void *)encode:(const void *)data
            dataBytes:(size_t)dataBytes
         encodedBytes:(size_t *)encodedBytes
               status:(mte_status *)status;
-(NSString *)encodeB64:(const void *)data
             dataBytes:(size_t)dataBytes
                status:(mte_status *)status;

// Encode the given string. Returns the encoded version and sets *encodedBytes
// to the length of the encoded version in bytes and *status to the status. The
// Base64 version returns a null-terminated Base64-encoded version instead.
-(const void *)encode:(NSString *)str
         encodedBytes:(size_t *)encodedBytes
               status:(mte_status *)status;
-(NSString *)encodeB64:(NSString *)str
                status:(mte_status *)status;

// Encode the given data of the given length at the given offset to the
// given buffer at the given offset. Returns the status. Sets *encOff to the
// offset of the encoded version. Sets *encBytes to the encoded length in
// bytes. The encoded buffer must have sufficient length remaining after
// the offset. Use getBuffBytes: or getBuffBytes64: to determine the
// buffer requirement for raw or Base64 respectively.
-(mte_status)encode:(const void *)data
            dataOff:(size_t)dataOff
          dataBytes:(size_t)dataBytes
            encoded:(void *)encoded
             encOff:(size_t *)encOff
           encBytes:(size_t *)encBytes;
-(mte_status)encodeB64:(const void *)data
               dataOff:(size_t)dataOff
             dataBytes:(size_t)dataBytes
               encoded:(void *)encoded
                encOff:(size_t *)encOff
              encBytes:(size_t *)encBytes;

// Uninstantiate the encoder. It is no longer usable after this call. Returns
// the status.
-(mte_status)uninstantiate;

@end


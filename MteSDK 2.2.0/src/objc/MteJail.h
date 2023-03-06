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

// This defines the jailbreak detection algorithm to use or simulate.
typedef enum MteJailAlgo_
{
  // No choice made.
  mteJailAlgoNone,

  // Android ARM32 device.
  mteJailAlgoAndroidArm32Dev,

  // Android ARM64 device.
  mteJailAlgoAndroidArm64Dev,

  // Android x86 simulator.
  mteJailAlgoAndroidX86Sim,

  // Android x86_64 simulator.
  mteJailAlgoAndroidX86_64Sim,

  // iOS ARM64 device.
  mteJailAlgoIosArm64Dev,

  // iOS x86_64 simulator.
  mteJailAlgoIosX86_64Sim,

  // Number of algorithms.
  numMteJailAlgo
} MteJailAlgo;
extern const char *MteJailAlgos[numMteJailAlgo];

// Class MteJail
//
// This is a helper to mutate the nonce according to the chosen algorithm.
@interface MteJail : NSObject<MteNonceCallback>
{
  // Jailbreak algorithm.
  MteJailAlgo myAlgo;

  // Nonce seed.
  uint8_t mySeed[sizeof(uint64_t)];
}

// Set the jailbreak algorithm to pair with. Defaults to mteJailAlgoNone.
-(void)setAlgo:(MteJailAlgo)algo;

// Set the nonce seed.
-(void)setNonceSeed:(uint64_t)seed;

// The nonce callback.
-(void)nonceCallbackWithMinLength:(uint32_t)minLength
                        maxLength:(uint32_t)maxLength
                            nonce:(void *)nonce
                           nBytes:(uint32_t *)nBytes;

@end


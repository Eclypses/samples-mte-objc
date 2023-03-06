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
#import "MteJail.h"
#import "mte_jail.h"

#import <string.h>

const char *MteJailAlgos[] =
{
  "None",
  "AndroidArm32Dev",
  "AndroidArm64Dev",
  "AndroidX86Sim",
  "AndroidX86_64Sim",
  "IosArm64Dev",
  "IosX86_64Sim"
};

@implementation MteJail

-(void)setAlgo:(MteJailAlgo)algo
{
  myAlgo = algo;
}

-(void)setNonceSeed:(uint64_t)seed
{
  for (size_t i = 0; i < sizeof(mySeed); ++i)
  {
    mySeed[i] = (uint8_t)((seed >> (i * 8)) & 0xFF);
  }
}

-(void)nonceCallbackWithMinLength:(uint32_t)minLength
                        maxLength:(uint32_t)maxLength
                            nonce:(void *)nonce
                           nBytes:(uint32_t *)nBytes
{
  size_t amt;
  switch (myAlgo)
  {
    case mteJailAlgoNone:
    case numMteJailAlgo:
      amt = sizeof(mySeed) > maxLength ? maxLength : sizeof(mySeed);
      memcpy(nonce, mySeed, amt);
      if (amt < minLength)
      {
        memset((uint8_t *)nonce + amt, 0, minLength - amt);
        *nBytes = (uint32_t)minLength;
      }
      else
      {
        *nBytes = (uint32_t)amt;
      }
      break;

    case mteJailAlgoAndroidArm32Dev:
      mte_jail_n_cb_android_arm32_d(mySeed,
                                    (uint32_t)sizeof(mySeed),
                                    minLength,
                                    maxLength,
                                    nonce,
                                    nBytes);
      break;

    case mteJailAlgoAndroidArm64Dev:
      mte_jail_n_cb_android_arm64_d(mySeed,
                                    (uint32_t)sizeof(mySeed),
                                    minLength,
                                    maxLength,
                                    nonce,
                                    nBytes);
      break;

    case mteJailAlgoAndroidX86Sim:
      mte_jail_n_cb_android_x86_s(mySeed,
                                  (uint32_t)sizeof(mySeed),
                                  minLength,
                                  maxLength,
                                  nonce,
                                  nBytes);
      break;

    case mteJailAlgoAndroidX86_64Sim:
      mte_jail_n_cb_android_x86_64_s(mySeed,
                                     (uint32_t)sizeof(mySeed),
                                     minLength,
                                     maxLength,
                                     nonce,
                                     nBytes);
      break;

    case mteJailAlgoIosArm64Dev:
      mte_jail_n_cb_ios_arm64_d(mySeed,
                                (uint32_t)sizeof(mySeed),
                                minLength,
                                maxLength,
                                nonce,
                                nBytes);
      break;

    case mteJailAlgoIosX86_64Sim:
      mte_jail_n_cb_ios_x86_64_s(mySeed,
                                 (uint32_t)sizeof(mySeed),
                                 minLength,
                                 maxLength,
                                 nonce,
                                 nBytes);
      break;
  }
}

@end


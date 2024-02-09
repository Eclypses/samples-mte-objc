// THIS SOFTWARE MAY NOT BE USED FOR PRODUCTION. Otherwise,
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
#import "MteDec.h"

#import <stdio.h>
#import <stdlib.h>
#import <string.h>

int main(int argc, char **argv)
{
#pragma unused(argc, argv)

  // Status.
  mte_status status;

  // Autorelease pool.
@autoreleasepool {
    puts("******  Simple MTE Sequencing Console Demo  ******");

  // Inputs.
  NSString *inputs[] =
  {
    MTE_AUTORELEASE([[NSString alloc] initWithUTF8String:"message 0"]),
    MTE_AUTORELEASE([[NSString alloc] initWithUTF8String:"message 1"]),
    MTE_AUTORELEASE([[NSString alloc] initWithUTF8String:"message 2"]),
    MTE_AUTORELEASE([[NSString alloc] initWithUTF8String:"message 3"])
  };

  // Personalization string.
  NSString *personal =
    MTE_AUTORELEASE([[NSString alloc] initWithUTF8String:"demo"]);

  // Initialize MTE license. If a license code is not required (e.g., trial
  // mode), this can be skipped. This demo attempts to load the license info
  // from the environment if required.
  if (![MteBase initLicense:@"YOUR_COMPANY" code:@"YOUR_LICENSE"])
  {
    const char *company = getenv("MTE_COMPANY");
    const char *license = getenv("MTE_LICENSE");
    if (company == NULL || license == NULL ||
      ![MteBase initLicense:
        MTE_AUTORELEASE([[NSString alloc] initWithUTF8String:company])
                       code:
        MTE_AUTORELEASE([[NSString alloc] initWithUTF8String:license])])
    {
      status = mte_status_license_error;
      fprintf(stderr, "License init error (%s): %s\n",
              [[MteBase getStatusName:status] UTF8String],
              [[MteBase getStatusDescription:status] UTF8String]);
      return status;
    }
  }

  // Create the encoder.
  MteEnc *encoder = MTE_AUTORELEASE([[MteEnc alloc] init]);

  // Create all-zero entropy for this demo. The nonce will also be set to 0.
  // This should never be done in real applications.
  size_t entropyBytes = [MteBase getDrbgsEntropyMinBytes:[encoder getDrbg]];
  uint8_t *entropy = calloc(entropyBytes, sizeof(uint8_t));

  // Instantiate the encoder.
  [encoder setEntropy:entropy bytes:entropyBytes];
  [encoder setNonce:0];
  status = [encoder instantiate:personal];
  if (status != mte_status_success)
  {
    fprintf(stderr, "Encoder instantiate error (%s): %s\n",
            [[MteBase getStatusName:status] UTF8String],
            [[MteBase getStatusDescription:status] UTF8String]);
    return status;
  }

  // Encode the inputs.
  NSString *encodings[sizeof(inputs) / sizeof(inputs[0])];
  for (unsigned i = 0; i < sizeof(inputs) / sizeof(inputs[0]); ++i)
  {
    encodings[i] = [encoder encodeB64:inputs[i] status:&status];
    if (status != mte_status_success)
    {
      fprintf(stderr, "Encode error (%s): %s\n",
              [[MteBase getStatusName:status] UTF8String],
              [[MteBase getStatusDescription:status] UTF8String]);
      return status;
    }
    printf("Encode #%u: %s -> %s\n",
           i,
           [inputs[i] UTF8String],
           [encodings[i] UTF8String]);
  }

  // Create decoders with different sequence windows.
  MteDec *decoderV = MTE_AUTORELEASE([[MteDec alloc] initWithTWindow:0
                                                             sWindow:0]);
  MteDec *decoderF = MTE_AUTORELEASE([[MteDec alloc] initWithTWindow:0
                                                             sWindow:2]);
  MteDec *decoderA = MTE_AUTORELEASE([[MteDec alloc] initWithTWindow:0
                                                             sWindow:-2]);

  // Instantiate the decoders.
  [decoderV setEntropy:entropy bytes:entropyBytes];
  [decoderV setNonce:0];
  status = [decoderV instantiate:personal];
  if (status == mte_status_success)
  {
    [decoderF setEntropy:entropy bytes:entropyBytes];
    [decoderF setNonce:0];
    status = [decoderF instantiate:personal];
    if (status == mte_status_success)
    {
      [decoderA setEntropy:entropy bytes:entropyBytes];
      [decoderA setNonce:0];
      status = [decoderA instantiate:personal];
    }
  }
  if (status != mte_status_success)
  {
    fprintf(stderr, "Decoder instantiate error (%s): %s\n",
            [[MteBase getStatusName:status] UTF8String],
            [[MteBase getStatusDescription:status] UTF8String]);
    return status;
  }

  // Save the async decoder state.
  size_t stateBytes;
  const void *dsaved = [decoderA saveState:&stateBytes];

  // String to decode to.
  NSString *decoded;

  // Create the corrupt version of message #2.
  char first[] = { [encodings[2] UTF8String][0] + 1, '\0' };
  NSString *nsfirst = [[NSString alloc] initWithUTF8String:first];
  NSString *corrupt =
    [encodings[2] stringByReplacingCharactersInRange:NSMakeRange(0, 1)
                                          withString:nsfirst];

  // Decode in verification-only mode.
  puts("\nVerification-only mode (sequence window = 0):");
  decoded = [decoderV decodeB64:encodings[0] status:&status];
  printf("Decode #0: %s, %s\n",
         mte_base_status_name(status),
         status == mte_status_success ? [decoded UTF8String] : "");
  decoded = [decoderV decodeB64:encodings[0] status:&status];
  printf("Decode #0: %s, %s\n",
         mte_base_status_name(status),
         status == mte_status_success ? [decoded UTF8String] : "");
  decoded = [decoderV decodeB64:encodings[2] status:&status];
  printf("Decode #2: %s, %s\n",
         mte_base_status_name(status),
         status == mte_status_success ? [decoded UTF8String] : "");
  decoded = [decoderV decodeB64:encodings[1] status:&status];
  printf("Decode #1: %s, %s\n",
         mte_base_status_name(status),
         status == mte_status_success ? [decoded UTF8String] : "");
  decoded = [decoderV decodeB64:encodings[2] status:&status];
  printf("Decode #2: %s, %s\n",
         mte_base_status_name(status),
         status == mte_status_success ? [decoded UTF8String] : "");
  decoded = [decoderV decodeB64:encodings[3] status:&status];
  printf("Decode #3: %s, %s\n",
         mte_base_status_name(status),
         status == mte_status_success ? [decoded UTF8String] : "");

  // Decode in forward-only mode.
  puts("\nForward-only mode (sequence window = 2):");
  decoded = [decoderF decodeB64:encodings[0] status:&status];
  printf("Decode #0: %s, %s\n",
         mte_base_status_name(status),
         status == mte_status_success ? [decoded UTF8String] : "");
  decoded = [decoderF decodeB64:encodings[0] status:&status];
  printf("Decode #0: %s, %s\n",
         mte_base_status_name(status),
         status == mte_status_success ? [decoded UTF8String] : "");
  decoded = [decoderF decodeB64:corrupt status:&status];
  printf("Corrupt #2: %s, %s\n",
         mte_base_status_name(status),
         status == mte_status_success ? [decoded UTF8String] : "");
  decoded = [decoderF decodeB64:encodings[2] status:&status];
  printf("Decode #2: %s, %s\n",
         mte_base_status_name(status),
         status == mte_status_success ? [decoded UTF8String] : "");
  decoded = [decoderF decodeB64:encodings[1] status:&status];
  printf("Decode #1: %s, %s\n",
         mte_base_status_name(status),
         status == mte_status_success ? [decoded UTF8String] : "");
  decoded = [decoderF decodeB64:encodings[2] status:&status];
  printf("Decode #2: %s, %s\n",
         mte_base_status_name(status),
         status == mte_status_success ? [decoded UTF8String] : "");
  decoded = [decoderF decodeB64:encodings[3] status:&status];
  printf("Decode #3: %s, %s\n",
         mte_base_status_name(status),
         status == mte_status_success ? [decoded UTF8String] : "");

  // Decode in async mode.
  puts("\nAsync mode (sequence window = -2):");
  decoded = [decoderA decodeB64:encodings[0] status:&status];
  printf("Decode #0: %s, %s\n",
         mte_base_status_name(status),
         status == mte_status_success ? [decoded UTF8String] : "");
  decoded = [decoderA decodeB64:encodings[0] status:&status];
  printf("Decode #0: %s, %s\n",
         mte_base_status_name(status),
         status == mte_status_success ? [decoded UTF8String] : "");
  decoded = [decoderA decodeB64:corrupt status:&status];
  printf("Corrupt #2: %s, %s\n",
         mte_base_status_name(status),
         status == mte_status_success ? [decoded UTF8String] : "");
  decoded = [decoderA decodeB64:encodings[2] status:&status];
  printf("Decode #2: %s, %s\n",
         mte_base_status_name(status),
         status == mte_status_success ? [decoded UTF8String] : "");
  decoded = [decoderA decodeB64:encodings[2] status:&status];
  printf("Decode #2: %s, %s\n",
         mte_base_status_name(status),
         status == mte_status_success ? [decoded UTF8String] : "");
  decoded = [decoderA decodeB64:encodings[1] status:&status];
  printf("Decode #1: %s, %s\n",
         mte_base_status_name(status),
         status == mte_status_success ? [decoded UTF8String] : "");
  decoded = [decoderA decodeB64:encodings[2] status:&status];
  printf("Decode #2: %s, %s\n",
         mte_base_status_name(status),
         status == mte_status_success ? [decoded UTF8String] : "");
  decoded = [decoderA decodeB64:encodings[3] status:&status];
  printf("Decode #3: %s, %s\n",
         mte_base_status_name(status),
         status == mte_status_success ? [decoded UTF8String] : "");

  // Restore and decode again in a different order.
  [decoderA restoreState:dsaved];
  puts("\nAsync mode (sequence window = -2):");
  decoded = [decoderA decodeB64:encodings[3] status:&status];
  printf("Decode #3: %s, %s\n",
         mte_base_status_name(status),
         status == mte_status_success ? [decoded UTF8String] : "");
  decoded = [decoderA decodeB64:encodings[0] status:&status];
  printf("Decode #0: %s, %s\n",
         mte_base_status_name(status),
         status == mte_status_success ? [decoded UTF8String] : "");
  decoded = [decoderA decodeB64:encodings[2] status:&status];
  printf("Decode #2: %s, %s\n",
         mte_base_status_name(status),
         status == mte_status_success ? [decoded UTF8String] : "");
  decoded = [decoderA decodeB64:encodings[1] status:&status];
  printf("Decode #1: %s, %s\n",
         mte_base_status_name(status),
         status == mte_status_success ? [decoded UTF8String] : "");

  free(entropy);
}

  // Success.
  return 0;
}


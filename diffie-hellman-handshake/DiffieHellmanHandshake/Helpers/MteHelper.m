/* Copyright (c) Eclypses, Inc. */
/*  */
/* All rights reserved. */
/*  */
/* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS */
/* OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF */
/* MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. */
/* IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY */
/* CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, */
/* TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE */
/* SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE. */


#import <Foundation/Foundation.h>
#import "MteHelper.h"
#import "MteBase.h"
#import "MteEnc.h"
#import "MteDec.h"
#import "Cbs.h"

@implementation MteHelper : NSObject

- (id)initWithSettings: (Settings *)settings {
    if(self = [super init]) {
        printf("%s\n", [[NSString stringWithFormat:@"Using MTE Version %@", [MteBase getVersion]] UTF8String]);
        
        if (![MteBase initLicense:@"CompanyName" code:@"CompanyKey"]) {
            puts("License Check Failed");
            return self;
        }
        puts("License Check Succeeded");
        _cbs = MTE_AUTORELEASE([[Cbs alloc] init]);
        _cbs.mteHelper = self;
        _cbs.settings = settings;
    }
    return self;
}

- (void)createEncoder {
    _encoder = [[MteEnc alloc] init];
    [self instantiateEncoder:_encoder];
}

-(void)instantiateEncoder:(MteEnc *)encoder {
    [encoder setEntropyCallback:_cbs];
    [encoder setNonceCallback:_cbs];
    _cbs.pairType = ENC;
    mte_status status = [encoder instantiate:_encoderPersonalization];
    if (status != mte_status_success) {
        printf("Instantiate Encoder error (%s): %s\n",
               [[MteBase getStatusName:status] UTF8String],
               [[MteBase getStatusDescription:status] UTF8String]);
        return;
    }
    puts("Encoder successfully Instantiated");
}


- (void)createDecoder {
    _decoder = [[MteDec alloc] init];
    [self instantiateDecoder:_decoder];
}

-(void)instantiateDecoder:(MteDec *)decoder {
    [decoder setEntropyCallback:_cbs];
    [decoder setNonceCallback:_cbs];
    _cbs.pairType = DEC;
    mte_status status = [decoder instantiate:_decoderPersonalization];
    if (status != mte_status_success) {
        printf("Instantiate Decoder error (%s): %s\n",
               [[MteBase getStatusName:status] UTF8String],
               [[MteBase getStatusDescription:status] UTF8String]);
        return;
    }
    puts("Decoder successfully Instantiated");
}

-(NSString *)encode:(NSString *)plaintext {
    mte_status status;
    NSString *encoded = [_encoder encodeB64:plaintext status:&status];
    if (status != mte_status_success)
    {
      fprintf(stderr, "Encode error (%s): %s\n",
              [[MteBase getStatusName:status] UTF8String],
              [[MteBase getStatusDescription:status] UTF8String]);
    }
    return encoded;
}

- (NSString *)decode:(NSString *)encoded {
    mte_status status;
    NSString *decoded = [_decoder decodeB64:encoded status:&status];
    if ([MteBase statusIsError:status])
    {
      fprintf(stderr, "Decode error (%s): %s\n",
              [[MteBase getStatusName:status] UTF8String],
              [[MteBase getStatusDescription:status] UTF8String]);
    }
    else if (status != mte_status_success)
    {
      fprintf(stderr, "Decode warning (%s): %s\n",
              [[MteBase getStatusName:status] UTF8String],
              [[MteBase getStatusDescription:status] UTF8String]);
    }
    return decoded;
}

@end

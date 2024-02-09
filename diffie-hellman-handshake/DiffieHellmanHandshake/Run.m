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
#import "Run.h"
#import "MteHelper.h"
#import "AppSettings.h"


@implementation Run

NSString *plaintext = @"This is our super secret data!";
NSString *encoded;
NSString *encodedResponse;

- (id)init {
    if(self = [super init]) {
        _settings = [[Settings alloc] init];
        _settings.clientId = [[NSUUID UUID] UUIDString];
    }
    return self;
}

- (void)start {
    Manager *manager = [[Manager alloc] initWithSettings:_settings];
    manager.delegate = self;

    _mteHelper = [[MteHelper alloc] initWithSettings:_settings];

    // Create Encoder
    _mteHelper.encoderPersonalization = [[NSUUID UUID] UUIDString];
    [_mteHelper createEncoder];

    // Create Decoder
    _mteHelper.decoderPersonalization = [[NSUUID UUID] UUIDString];
    [_mteHelper createDecoder];

    encoded = [_mteHelper encode:@"This is our super secret data!"];
    [manager send:encoded];
}


- (void)sendDataResponse:(id)response {
    NSString *decoded = [_mteHelper decode:response];
    printf("\n\n... and our Decoded response from the Server is -> %s\n", [decoded UTF8String]);
    printf("\n\nHit [ENTER] to quit.");
}

@end

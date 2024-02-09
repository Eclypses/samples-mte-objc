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

#ifndef MteHelper_h
#define MteHelper_h


#endif /* MteHelper_h */

#import "DiffieHellmanHandshake-Swift.h"
@class MteEnc;
@class MteDec;
@class Cbs;
@class Settings;

@interface MteHelper : NSObject

// Initial Values
@property (nonatomic, strong) NSString *encoderPersonalization, *decoderPersonalization;
@property (nonatomic, strong) NSMutableArray *encoderEntropy, *decoderEntropy;
@property (nonatomic) UInt64 encoderNonce, decoderNonce;
@property (nonatomic, strong) MteEnc *encoder;
@property (nonatomic, strong) MteDec *decoder;
@property (nonatomic, strong) Cbs *cbs;


- (id)initWithSettings: (Settings *)settings;

- (void)createEncoder;
- (void)instantiateEncoder:(MteEnc *)encoder;
- (NSString *)encode:(NSString *)plaintext;

- (void)createDecoder;
- (void)instantiateDecoder:(MteDec *)decoder;
- (NSString *)decode:(NSString *)encoded;


@end

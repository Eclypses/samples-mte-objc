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

#ifndef Cbs_h
#define Cbs_h


#endif /* Cbs_h */

@class MteHelper;
@class Settings;
#import "MteBase.h"


@interface Cbs : NSObject<MteEntropyCallback, MteNonceCallback, MteTimestampCallback>

typedef enum {
    ENC,
    DEC
} PairType;

@property (nonatomic) PairType pairType;
@property (nonatomic) MteHelper *mteHelper;
@property (nonatomic) Settings *settings;
@property (nonatomic) uint64_t tempEncoderNonce;
@property (nonatomic) uint64_t tempDecoderNonce;


-(mte_status)entropyCallback:(mte_drbg_ei_info *)info;
-(void)nonceCallback:(mte_drbg_nonce_info *)info;
-(uint64_t)timestampCallback;

@end

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
#import "Cbs.h"
#import "MteHelper.h"
#import "AppSettings.h"

@implementation Cbs

-(mte_status)entropyCallback:(mte_drbg_ei_info *)info {
    NSError *error;
    switch(_pairType) {
        case ENC: {
            @autoreleasepool {
                puts("\nCalling to get Encoder Entropy");
                NSString *name = @"ENC";
                EcdhHelper *ecdhHelper = [[EcdhHelper alloc] initWithName:name error:&error];
                if (error) {
                    NSLog(@"Error creating ecdhHelper: %@", error);
                }
                NSString *publicKey = [ecdhHelper getPublicKeyAndReturnError:&error];
                if (error) {
                    NSLog(@"Error creating device public key: %@", error);
                }
                // Create NSMutableURLRequest as required.
                NSString *payload = [NSString stringWithFormat:@"%@%@%@%@%@%@%s", @"{\"personalizationString\":\"", _mteHelper.encoderPersonalization, @"\",\"publicKey\":\"", publicKey, @"\",\"pairType\":\"", name, "\"}"];
                NSData *payloadData = [payload dataUsingEncoding:NSUTF8StringEncoding];
                NSString *route = @"api/pairone";
                NSURL *url = [NSURL URLWithString:[NSString stringWithFormat:@"%@%@", _settings.serverUrl, route]];
                NSMutableURLRequest *request = [[NSMutableURLRequest alloc] initWithURL:url];
                [request setHTTPMethod:@"POST"];
                [request setValue: _settings.clientId forHTTPHeaderField:@"x-client-id"];
                [request setHTTPBody:payloadData];
                [request setValue:@"application/json; charset=UTF-8" forHTTPHeaderField:@"Content-Type"];
                
                // Pausing to wait for response from server. Perhaps not the best way to handle this
                dispatch_semaphore_t sema = dispatch_semaphore_create(0);
                NSURLSessionDataTask *task = [[NSURLSession sharedSession]
                                              dataTaskWithRequest:request completionHandler:^(NSData *data,
                                                                                              NSURLResponse *response,
                                                                                              NSError *error) {
                    id jsonObject = [NSJSONSerialization JSONObjectWithData:data options:0 error:&error];
                    if (error) {
                        NSLog(@"Error parsing JSON: %@", error);
                    } else {
                        static char eiBuff[32];
                        size_t inputBytes;
                        NSDictionary *jsonDictionary = (NSDictionary *)jsonObject;
                        
                        // Assign encoderNonce to local variable where it will be accessible to the nonceCallback.
                        self->_tempEncoderNonce = (uint64)[[jsonDictionary valueForKey:@"timestamp"] integerValue];
                        NSArray<NSNumber *> *tempEntropy = [ecdhHelper createSharedSecretWithRemotePublicKeyStr:[jsonDictionary objectForKey:@"publicKey"] error:&error];
                        inputBytes = (unsigned long)tempEntropy.count;
                    
                        // Fill the buffer
                        for (int i=0; i<[tempEntropy count]; i++) {
                            NSInteger value = [[tempEntropy objectAtIndex:i] integerValue];
                            eiBuff[i] = value;
                        }
                        
                        // Check the length
                        if (inputBytes < info->min_length)
                        {
                            puts("Encoder Entropy too short");
                        }
                        else
                        {
                          /* Point at our buffer. */
                          info->buff = (MTE_UINT8_T *)eiBuff;
                        }

                        /* Set the actual entropy length. */
                        info->bytes = (MTE_SIZE_T)inputBytes;

                        dispatch_semaphore_signal(sema);
                    }
                }];
                [task resume];
                if (![NSThread isMainThread]) {
                    dispatch_semaphore_wait(sema, DISPATCH_TIME_FOREVER);
                } else {
                    while (dispatch_semaphore_wait(sema, DISPATCH_TIME_NOW)) {
                        [[NSRunLoop currentRunLoop] runMode:NSDefaultRunLoopMode beforeDate:[NSDate dateWithTimeIntervalSinceNow:0]];
                    }
                }
                break;
            }
        }
        case DEC: {
            @autoreleasepool {
                puts("\nCalling to get Decoder Entropy");
                NSString *name = @"DEC";
                EcdhHelper *ecdhHelper = [[EcdhHelper alloc] initWithName:name error:&error];
                if (error) {
                    NSLog(@"Error instantiating ecdhHelper: %@", error);
                }
                NSString *publicKey = [ecdhHelper getPublicKeyAndReturnError:&error];
                if (error) {
                    NSLog(@"Error creating device public key: %@", error);
                }
                
                // Create NSMutableURLRequest as required.
                NSString *payload = [NSString stringWithFormat:@"%@%@%@%@%@%@%s", @"{\"personalizationString\":\"", _mteHelper.decoderPersonalization, @"\",\"publicKey\":\"", publicKey, @"\",\"pairType\":\"", name, "\"}"];
                NSData *payloadData = [payload dataUsingEncoding:NSUTF8StringEncoding];
                NSString *route = @"api/pairone";
                NSURL *url = [NSURL URLWithString:[NSString stringWithFormat:@"%@%@", _settings.serverUrl, route]];
                NSMutableURLRequest *request = [[NSMutableURLRequest alloc] initWithURL:url];
                [request setHTTPMethod:@"POST"];
                [request setValue:_settings.clientId forHTTPHeaderField:@"x-client-id"];
                [request setHTTPBody:payloadData];
                [request setValue:@"application/json; charset=UTF-8" forHTTPHeaderField:@"Content-Type"];
                dispatch_semaphore_t sema = dispatch_semaphore_create(0);
                
                // Pausing to wait for response from server. Perhaps not the best way to handle this
                NSURLSessionDataTask *task = [[NSURLSession sharedSession]
                                              dataTaskWithRequest:request completionHandler:^(NSData *data,
                                                                                              NSURLResponse *response,
                                                                                              NSError *error) {
                    id jsonObject = [NSJSONSerialization JSONObjectWithData:data options:0 error:&error];
                    if (error) {
                        NSLog(@"Error parsing JSON: %@", error);
                    } else {
                        static char eiBuff[32];
                        size_t inputBytes;
                        NSDictionary *jsonDictionary = (NSDictionary *)jsonObject;
                        
                        // Assign decoderNonce to local variable where it will be accessible to the nonceCallback.
                        self->_tempDecoderNonce = (uint64)[[jsonDictionary valueForKey:@"timestamp"] integerValue];
                                                
                        NSArray<NSNumber *> *tempEntropy = [ecdhHelper createSharedSecretWithRemotePublicKeyStr:[jsonDictionary objectForKey:@"publicKey"] error:&error];
                        inputBytes = (unsigned long)tempEntropy.count;
                        for (int i=0; i<[tempEntropy count]; i++) {
                            NSInteger value = [[tempEntropy objectAtIndex:i] integerValue];
                            eiBuff[i] = value;
                        }
                        
                        if (inputBytes < info->min_length)
                        {
                            NSLog(@"Decoder Entropy too short");
                        }
                        else
                        {
                          /* Point at our buffer. */
                          info->buff = (MTE_UINT8_T *)eiBuff;
                        }

                        /* Set the actual entropy length. */
                        info->bytes = (MTE_SIZE_T)inputBytes;
                        dispatch_semaphore_signal(sema);
                    }
                }];
                [task resume];
                if (![NSThread isMainThread]) {
                    dispatch_semaphore_wait(sema, DISPATCH_TIME_FOREVER);
                } else {
                    while (dispatch_semaphore_wait(sema, DISPATCH_TIME_NOW)) {
                        [[NSRunLoop currentRunLoop] runMode:NSDefaultRunLoopMode beforeDate:[NSDate dateWithTimeIntervalSinceNow:0]];
                    }
                }
                break;
            }
        }
    }
    return mte_status_success;
}

-(void)nonceCallback:(mte_drbg_nonce_info *)info {
    size_t i;
    switch(_pairType) {
        case ENC: {
            puts("Entered Encoder NonceCallback");

            // Copy the tempEncoderNonce in little-endian format to the nonce buffer.
            for (i = 0; i < info->max_length && i < sizeof(_tempEncoderNonce); ++i)
            {
                info->buff[i] = (MTE_UINT8_T)(_tempEncoderNonce >> (i * 8));
            }
            break;
        }
        case DEC: {
            puts("Entered Decoder NonceCallback");
            
            // Copy the tempDecoderNonce in little-endian format to the nonce buffer.
            for (i = 0; i < info->max_length && i < sizeof(_tempDecoderNonce); ++i)
            {
                info->buff[i] = (MTE_UINT8_T)(_tempDecoderNonce >> (i * 8));
            }
            break;
        }
    }
    // If the minimum length is greater than the size of the nonce we got, fill
    // up to that length with zeros.
    for (; i < info->min_length; ++i)
    {
        info->buff[i] = 0;
    }
    
    // Set the actual nonce length.
    info->bytes = (MTE_SIZE8_T)i;
}

- (uint64_t)timestampCallback {
    puts("We have entered timestamp callback");
    uint64_t timestamp = (uint64_t)[[NSDate date] timeIntervalSince1970];
    return timestamp;
}

@end

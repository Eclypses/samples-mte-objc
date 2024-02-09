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
#import "Manager.h"
#import "AppSettings.h"

@implementation Manager

- (id)initWithSettings: (Settings *)settings {
    if(self = [super init]) {
        _settings = settings;
    }
    return self;
}

-(void)send:(NSString *)encoded {
    NSString *payload = encoded;
    printf("\nPlaintext was encoded as -> %s", [encoded UTF8String]);
    NSData *payloadData = [payload dataUsingEncoding:NSUTF8StringEncoding];
    NSString *route = @"api/mte/send-data";
    NSURL *url = [NSURL URLWithString:[NSString stringWithFormat:@"%@%@", _settings.serverUrl, route]];
    NSMutableURLRequest *request = [[NSMutableURLRequest alloc] initWithURL:url];
    [request setHTTPMethod:@"POST"];
    [request setValue: _settings.clientId forHTTPHeaderField:@"x-client-id"];
    [request setHTTPBody:payloadData];
    [request setValue:@"text/plain; charset=utf-8" forHTTPHeaderField:@"Content-Type"];
    
    NSURLSessionDataTask *task = [[NSURLSession sharedSession]
                                  dataTaskWithRequest:request completionHandler:^(NSData *data,
                                                                                  NSURLResponse *response,
                                                                                  NSError *error) {
    
    NSString *myString = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    if ([self.delegate respondsToSelector:@selector(sendDataResponse:)]) {
        [self.delegate sendDataResponse:myString];
        }
    }];
    [task resume];
}

@end

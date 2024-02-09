//
// ******************************************************
// DiffieHellmanHandshake Project
// AppSettings.m created on 9/20/22 by Greg Waggoner
// 
// ******************************************************


#import <Foundation/Foundation.h>
#import "AppSettings.h"

@implementation Settings

- (id)init {
    if(self = [super init]) {
        _serverUrl = @"http://localhost:5000/";
    }
    return self;
}

@end

//
// ******************************************************
// DiffieHellmanHandshake Project
// Run.h created on 9/23/22 by Greg Waggoner
// 
// ******************************************************


#ifndef Run_h
#define Run_h


#endif /* Run_h */
@class MteHelper;
#import "Manager.h"


@interface Run : NSObject<sendDataDelegate>

- (void)start;

@property (nonatomic, strong) Settings *settings;
@property (nonatomic) MteHelper *mteHelper;

@end

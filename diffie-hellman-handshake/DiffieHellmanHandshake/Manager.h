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


#ifndef Manager_h
#define Manager_h


#endif /* Manager_h */

@protocol sendDataDelegate <NSObject>

- (void)sendDataResponse:(id)response;

@end

@class Settings;

@interface Manager : NSObject

@property (nonatomic) Settings *settings;
@property (nonatomic)id <sendDataDelegate> delegate;

- (id)initWithSettings: (Settings *)settings;
-(void)send:(NSString *)encoded;

@end

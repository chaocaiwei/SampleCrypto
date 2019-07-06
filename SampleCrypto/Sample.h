//
//  Sample.h
//  SampleCrypto
//
//  Created by myself on 2019/5/27.
//  Copyright © 2019 chaocaiwei. All rights reserved.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface Sample : NSObject

+ (CFDictionaryRef)getDictFromArray:(CFArrayRef)array;
+ (void)handleArray:(CFArrayRef)array;
+ (void)handle:(CFDictionaryRef)dict;

@end

NS_ASSUME_NONNULL_END

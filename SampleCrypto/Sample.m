//
//  Sample.m
//  SampleCrypto
//
//  Created by myself on 2019/5/27.
//  Copyright © 2019 chaocaiwei. All rights reserved.
//

#import "Sample.h"

@implementation Sample


+ (CFDictionaryRef)getDictFromArray:(CFArrayRef)array
{
    const void *identityDict = CFArrayGetValueAtIndex(array, 0);
    return identityDict;
}

+ (void)handleArray:(CFArrayRef)array
{
    CFDictionaryRef identityDict = CFArrayGetValueAtIndex(array, 0);
    [self handle:identityDict];
    SecIdentityRef identityApp =(SecIdentityRef)CFDictionaryGetValue(identityDict,kSecImportItemIdentity);
    SecKeyRef privateKeyRef=nil;
    SecIdentityCopyPrivateKey(identityApp, &privateKeyRef);
}

+ (void)handle:(CFDictionaryRef)dict
{
    CFStringRef key = kSecImportItemIdentity;
    id value = CFDictionaryGetValue(dict, key);
    NSLog(@"%@",value);
}

@end

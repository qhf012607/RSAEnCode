//
//  test.h
//  kz
//
//  Created by Tech_001 on 4/8/2017.
//  Copyright © 2017 Tech_001. All rights reserved.
//
#import <Foundation/Foundation.h>

@interface RSAHelper : NSObject
+ (void)generateKey;
+ (NSString *)getBase64Modulus;
+ (NSString *)getExponent;
+ (NSString *)getN;
+ (NSString *)getD;
+ (NSString *)decrypt:(NSString *) strEncryptBase64ed;
+ (NSString *)encrypt:(NSString *)data;
+ (NSString *)encrypt:(NSString *)data modulus:(NSString *)modulus exponent:(NSString *)exponent;
@end

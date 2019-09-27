//
//  test.m
//  kz
//
//  Created by Tech_001 on 4/8/2017.
//  Copyright © 2017 Tech_001. All rights reserved.
//
#import "RSAHelper.h"
#import <Foundation/Foundation.h>
#import "Base64.h"
#import "RSAEncryptor.h"
#include "md5.h"
#include "rsa.h"
#include "pem.h"
#import <UIKit/UIKit.h>
#include <stdlib.h>
#include <stdio.h>

@implementation RSAHelper
static RSA *regRsa;
static NSString *n;
static NSString *e;
static NSString *d;

+ (void)generateKey{
    RSA *rsa = RSA_generate_key(1024, 0x10001, NULL, NULL);
    
    BIGNUM *bne =BN_new();
    //    unsigned int e = RSA_3;
    unsigned int e = 0x10001;
    int result = BN_set_word(bne, e);
    
    result = RSA_generate_key_ex(rsa, 1024, bne, NULL);
    //PEM_write_RSAPrivateKey(stdout, rsa, NULL, NULL, 0, NULL, NULL);
    //PEM_write_RSAPublicKey(stdout, rsa);
    
    
    regRsa = rsa;
    NSLog(@"d=%@", [self getD]);
    NSLog(@"n=%@", [self getN]);
    NSLog(@"E=%@", [self getExponent]);
    
    /**** ****/
    /*NSString *modulus = [Base64 stringByEncodingData:[self convertHexStrToData:[self getN]]];
    NSString *encrypt = [self encrypt:@"1234" modulus:modulus exponent:@"AQAB"];
    
    NSLog(@"Modulus: %@", modulus);
    NSLog(@"Encrypt: %@", encrypt);
    NSLog(@"Decrypt: %@", [self decrypt:encrypt]);*/
}

+(NSString *)getBase64Modulus{
    return [Base64 stringByEncodingData:[self convertHexStrToData:[self getN]]];
}

+(NSString *)getN{
    
    if(n){
        return n;
    }
    if (!regRsa) {
        [RSAHelper generateKey];
    }
    
    unsigned char *data = malloc(BN_num_bytes(regRsa->n));
    int length = BN_bn2bin(regRsa->n, data);
    NSData *testData = [NSData dataWithBytesNoCopy:data length:length];
    n = [self convertDataToHexStr:testData];
    return n;
}
//d
+(NSString *)getD{
    
    if(!d){
        return d;
    }
    unsigned char *data = malloc(BN_num_bytes(regRsa->d));
    int length = BN_bn2bin(regRsa->d, data);
    NSData *testData = [NSData dataWithBytesNoCopy:data length:length];
    d = [self convertDataToHexStr:testData];
    return d;
}
//e
+(NSString *)getExponent{
    //    return @"AQAB";
    if(!e){
        return e;
    }
    unsigned char *data = malloc(BN_num_bytes(regRsa->e));
    int length = BN_bn2bin(regRsa->e, data);
    NSData *testData = [NSData dataWithBytesNoCopy:data length:length];
    e = [self convertDataToHexStr:testData];
    return e;
}

+ (NSString *)convertDataToHexStr:(NSData *)data {
    if (!data || [data length] == 0) {
        return @"";
    }
    NSMutableString *string = [[NSMutableString alloc] initWithCapacity:[data length]];
    
    [data enumerateByteRangesUsingBlock:^(const void *bytes, NSRange byteRange, BOOL *stop) {
        unsigned char *dataBytes = (unsigned char*)bytes;
        for (NSInteger i = 0; i < byteRange.length; i++) {
            NSString *hexStr = [NSString stringWithFormat:@"%x", (dataBytes[i]) & 0xff];
            if ([hexStr length] == 2) {
                [string appendString:hexStr];
            } else {
                [string appendFormat:@"0%@", hexStr];
            }
        }
    }];
    
    return string;
}

+ (NSData *)convertHexStrToData:(NSString *)str {
    if (!str || [str length] == 0) {
        return nil;
    }
    
    NSMutableData *hexData = [[NSMutableData alloc] initWithCapacity:8];
    NSRange range;
    if ([str length] % 2 == 0) {
        range = NSMakeRange(0, 2);
    } else {
        range = NSMakeRange(0, 1);
    }
    for (NSInteger i = range.location; i < [str length]; i += 2) {
        unsigned int anInt;
        NSString *hexCharStr = [str substringWithRange:range];
        NSScanner *scanner = [[NSScanner alloc] initWithString:hexCharStr];
        
        [scanner scanHexInt:&anInt];
        NSData *entity = [[NSData alloc] initWithBytes:&anInt length:1];
        [hexData appendData:entity];
        
        range.location += range.length;
        range.length = 2;
    }
    
    //NSLog(@"hexdata: %@", hexData);
    return hexData;
}

+ (NSString *)decrypt:(NSString *) strEncryptBase64ed{
    RSA *r = regRsa;
    if(!r){
        [self generateKey];
        r = regRsa;
    }
    
    int blockLen;//每次最大加密字节数
    unsigned char *decodeData;//加密后的数据
    
    blockLen = RSA_size(r) - 11;// 公钥长度/8 - 11
    
    decodeData = (unsigned char *)malloc(blockLen);
    bzero(decodeData, blockLen);
    
    //由于需要加密的内容都在最大加密长度内，所以我没有分块，如果你的文本内容长度超过了blockLen，请分块处理，然后拼接起来
    
    NSData *dataFromSrc = [Base64 decodeString:strEncryptBase64ed];
    
    int retDecode = RSA_private_decrypt(128, [dataFromSrc bytes], decodeData, r, RSA_PKCS1_PADDING);
    
    if(retDecode > 0){
        //        NSData *result = [Base64 encodeBytes:decodeData length:retDecode];
        
        NSData *adata = [[NSData alloc] initWithBytes:decodeData length:retDecode];
        
        NSString *ans = [[NSString alloc] initWithData:adata encoding:NSUTF8StringEncoding];
        free(decodeData);
        //NSLog(@"%@", ans);
        return ans;
    }
    
    
    NSString *ans = @"";
    
    return ans;
}

+ (NSString *)encrypt:(NSString *)data{
    if(regRsa == NULL)
        [self generateKey];
        
    RSA r = *regRsa;
    int blockLen;//每次最大加密字节数
    unsigned char *encodeData;//加密后的数据
    blockLen = RSA_size(&r) - 11;// 公钥长度/8 - 11
    
    encodeData = (unsigned char *)malloc(blockLen);
    bzero(encodeData, blockLen);
    
    //由于需要加密的内容都在最大加密长度内，所以我没有分块，如果你的文本内容长度超过了blockLen，请分块处理，然后拼接起来
    
    int ret = RSA_public_encrypt([data length], (unsigned char *)[data UTF8String], encodeData, &r, RSA_PKCS1_PADDING);
    //这里的 RSA_PKCS1_PADDING选择的不同，对应的最大加密长度就不一样，当时在网上看到过，现在找不到了，你们自己上网找找吧
    
    
    if(ret < 0) {
        NSLog(@"encrypt failed !");
        return @"";
    }
    else {
        NSData *result = [Base64 encodeBytes:encodeData length:ret];
        free(encodeData);
        return [[NSString alloc] initWithData:result encoding:NSUTF8StringEncoding] ;
    }
}

+ (NSString *)encrypt:(NSString *)data modulus:(NSString *)modulus exponent:(NSString *)exponent{
    
    NSData *m = [Base64 decodeString:modulus];
    NSData *e = [Base64 decodeString:exponent];
    
    printf("Decoded modulus: %s\n", [[[NSString alloc] initWithData:m encoding:NSASCIIStringEncoding] UTF8String]);
    RSA *r;
    BIGNUM *bne, *bnn;//rsa算法中的 e和N
    int blockLen;//每次最大加密字节数
    unsigned char *encodeData;//加密后的数据
    
    bnn = BN_new();
    bne = BN_new();
    
    r = RSA_new();
    //看到网上有人用BN_hex2bn这个函数来转化的，但我用这个转化总是失败，最后选择了BN_bin2bn
    r->e = BN_bin2bn([e bytes], [e length], bne);
    r->n = BN_bin2bn([m bytes], [m length], bnn);
    
    blockLen = RSA_size(r) - 11;// 公钥长度/8 - 11
    
    encodeData = (unsigned char *)malloc(blockLen);
    bzero(encodeData, blockLen);
    
    //由于需要加密的内容都在最大加密长度内，所以我没有分块，如果你的文本内容长度超过了blockLen，请分块处理，然后拼接起来
    
    int ret = RSA_public_encrypt([data length], (unsigned char *)[data UTF8String], encodeData, r, RSA_PKCS1_PADDING);
    //这里的 RSA_PKCS1_PADDING选择的不同，对应的最大加密长度就不一样，当时在网上看到过，现在找不到了，你们自己上网找找吧
    
    
    RSA_free(r);
    if(ret < 0) {
        NSLog(@"encrypt failed !");
        return @"";
    }
    else {
        NSData *result = [Base64 encodeBytes:encodeData length:ret];
        free(encodeData);
        return [[NSString alloc] initWithData:result encoding:NSUTF8StringEncoding] ;
    }
}
@end


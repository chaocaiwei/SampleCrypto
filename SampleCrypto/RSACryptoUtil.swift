//
//  CryptoUtil.swift
//  SampleCrypto
//
//  Created by myself on 2019/5/28.
//  Copyright © 2019 chaocaiwei. All rights reserved.
//

import UIKit
import Security

struct RSACryptoUtil  {
    
    // 签名时用到的散列函数
    public enum DigestType {
        case md5
        case sha1
        case sha224
        case sha256
        case sha384
        case sha512
        case none
        
        var padding: SecPadding {
            switch self {
            case .md5: return .PKCS1MD5
            case .sha1: return .PKCS1SHA1
            case .sha224: return .PKCS1SHA224
            case .sha256: return .PKCS1SHA256
            case .sha384: return .PKCS1SHA384
            case .sha512: return .PKCS1SHA512
            case .none: return .PKCS1
            }
        }
    }
    
    /// 字符串的RSA加密
    ///
    /// - Parameters:
    ///   - string: 要加密的
    ///   - key: 公钥
    ///   - padding: pading值
    /// - Returns: 加密后数据的base64字符串
    static func encrypt(string:String,key:RSAKey,padding:SecPadding = .PKCS1)->String? {
        guard let data = string.data(using:.utf8) else {
            return nil
        }
        
        guard let encData = self.encrypt(data: data, key:key, padding:padding) else {
            return nil
        }
        
        return encData.base64EncodedString()
    }
    
    
    /// RSA加密
    ///
    /// - Parameters:
    ///   - data: 要加密的原式数据
    ///   - key: 公钥
    ///   - padding: padding值
    /// - Returns: 加密后的数据
    static func encrypt(data:Data,key:RSAKey,padding:SecPadding = .PKCS1)->Data? {
        return self.encrypt(data:data, key:key.reference, padding:padding)
    }
    
    
    private static func encrypt(data:Data,key:SecKey,padding:SecPadding = .PKCS1)->Data?{
        
        let blockSize = SecKeyGetBlockSize(key)
        // 数据分块的最大长度
        var maxChunkSize : Int
        switch padding {
        case .PKCS1:
            maxChunkSize = blockSize - 11
        case .OAEP:
            maxChunkSize = blockSize - 42
        case []: // no padding
            maxChunkSize = blockSize
        default: // default PKCS1
            maxChunkSize = blockSize - 11
        }
        
        var retData = Data()
        var idx = 0
        while idx < data.count {
            let endIdx = min(idx+maxChunkSize,data.count)
            var chunkData = [UInt8](data[idx..<endIdx])
            var outLen    = blockSize;
            let outBuf    = UnsafeMutablePointer<UInt8>.allocate(capacity:outLen)
            defer { outBuf.deallocate() }
            
            var status = noErr;
            status = SecKeyEncrypt(key,
                                   padding,
                                   &chunkData,
                                   chunkData.count,
                                   outBuf,
                                   &outLen)
            guard  status == noErr else {
                print("SecKeyEncrypt fail. Error Code: \(status)")
                return nil;
            }
            
            let ret1 = UnsafeBufferPointer(start:outBuf, count:outLen)
            retData.append(ret1)
            idx += maxChunkSize
        }
        return retData
    }
    
    /// 字符串的RSA解密
    ///
    /// - Parameters:
    ///   - string: 加密的字符串(base64)
    ///   - key: 私钥
    ///   - padding: padding值
    /// - Returns: 解密后得到的字符串
    static func decrypt(string:String,key:RSAKey,padding:SecPadding = .PKCS1)->String?{
        
        guard let data = Data(base64Encoded:string, options:.ignoreUnknownCharacters) else {
            return nil
        }
        
        guard let decryptData = self.decrypt(data:data, key:key, padding: padding) else {
            return nil
        }
        
        let ret = String(data: decryptData, encoding:.utf8)
        
        return ret
    }
    
    static func decrypt(data:Data,key:RSAKey,padding:SecPadding = .PKCS1)->Data? {
        return self.decrypt(data:data, key:key.reference, padding:padding)
    }
    
    private static func decrypt(data:Data,key:SecKey,padding:SecPadding = .PKCS1)->Data?{
        
        let blockSize = SecKeyGetBlockSize(key)
        var retData = Data()
        var idx = 0
        while idx < data.count {
            let endIdx = min(idx+blockSize,data.count)
            var chunkData = [UInt8](data[idx..<endIdx])
            var outLen    = blockSize;
            let outBuf    = UnsafeMutablePointer<UInt8>.allocate(capacity:outLen)
            defer { outBuf.deallocate() }
            
            var status = noErr;
            status = SecKeyDecrypt(key,
                                   padding,
                                   &chunkData,
                                   chunkData.count,
                                   outBuf,
                                   &outLen)
            guard  status == noErr else {
                print("SecKey decrypt fail. Error Code: \(status)")
                return nil;
            }
            
            let ret1 = UnsafeBufferPointer(start:outBuf, count:outLen)
            retData.append(ret1)
            idx += blockSize
        }
        return retData
    }
    
    /// 字符串的RSA签名
    ///
    /// - Parameters:
    ///   - string: 要签名的字符串
    ///   - key: 私钥
    ///   - digestType: 散列函数类型
    /// - Returns: 签名的base字符串
    static func sign(string:String,key:RSAKey,digestType:DigestType)->String?{
        
        guard let data = string.data(using:.utf8) else {
            return nil
        }
        
        guard let signData = self.sign(data:data, key:key, digestType: digestType) else {
            return nil
        }
        
        return signData.base64EncodedString()
    }
    
    
    /// RSA签名
    ///
    /// - Parameters:
    ///   - data: 原始数据
    ///   - key: 私钥
    ///   - digestType: 用到的散列函数
    /// - Returns: 签名
    static func sign(data:Data,key:RSAKey,digestType:DigestType)->Data?{
        return self.sign(data:data, key:key.reference, pading:digestType.padding)
    }
    
    private static func sign(data:Data,key:SecKey,pading:SecPadding)->Data?{
        
        // 先对原始数据进行散列函数运算
        var digestData : Data
        switch pading {
        case .PKCS1MD5:
            digestData = DigestUtil.md5(data:data)
        case .PKCS1SHA1:
            digestData = DigestUtil.sha1(data:data)
        case .PKCS1SHA1:
            digestData = DigestUtil.sha1(data:data)
        case .PKCS1SHA224:
            digestData = DigestUtil.sha224(data:data)
        case .PKCS1SHA256:
            digestData = DigestUtil.sha256(data:data)
        case .PKCS1SHA384:
            digestData = DigestUtil.sha384(data:data)
        case .PKCS1SHA512:
            digestData = DigestUtil.sha512(data:data)
        default:
            digestData = data
        }
        
        let blockSize = SecKeyGetBlockSize(key)
        var maxChunkSize : Int = blockSize - 11
        var retData = Data()
        var idx = 0
        while idx < digestData.count {
            let endIdx = min(idx+maxChunkSize,digestData.count)
            var chunkData = [UInt8](digestData[idx..<endIdx])
            var outLen = SecKeyGetBlockSize(key);
            let outBuf = UnsafeMutablePointer<UInt8>.allocate(capacity:outLen)
            defer { outBuf.deallocate() }
            var status = noErr;
            status = SecKeyRawSign(key,
                                   pading,
                                   &chunkData,
                                   chunkData.count,
                                   outBuf,
                                   &outLen)
            if status == noErr {
                let ret1 = UnsafeBufferPointer(start:outBuf, count:outLen)
                retData.append(ret1)
            }else {
                print("SecKey sign fail. Error Code: \(status)")
                return nil;
            }
            idx += maxChunkSize
        }
        return retData
    }
    
    
    static func  verify(string:String,sign:String,key:RSAKey,digest:DigestType)->Bool {
        guard let data = string.data(using: .utf8) else {
            return false
        }
        
        guard let signData = Data(base64Encoded:sign, options:.ignoreUnknownCharacters) else {
            return false
        }
        
        return self.verify(data:data, signData:signData, key:key, digest:digest)
    }
    
    static func  verify(data:Data,signData:Data,key:RSAKey,digest:DigestType)->Bool {
        return self.verify(data:data, signData:signData, key:key.reference, pading:digest.padding)
    }
    
    private static func verify(data:Data,signData:Data,key:SecKey,pading:SecPadding)->Bool{
        
        // 先对原始数据进行散列函数运算
        var digestData : Data
        switch pading {
        case .PKCS1MD5:
            digestData = DigestUtil.md5(data:data)
        case .PKCS1SHA1:
            digestData = DigestUtil.sha1(data:data)
        case .PKCS1SHA1:
            digestData = DigestUtil.sha1(data:data)
        case .PKCS1SHA224:
            digestData = DigestUtil.sha224(data:data)
        case .PKCS1SHA256:
            digestData = DigestUtil.sha256(data:data)
        case .PKCS1SHA384:
            digestData = DigestUtil.sha384(data:data)
        case .PKCS1SHA512:
            digestData = DigestUtil.sha512(data:data)
        default:
            digestData = data
        }
        
        var digestBuf = [UInt8](digestData)
        let signBuf   = [UInt8](signData)
        var status = noErr;
        status = SecKeyRawVerify(key,
                                 pading,
                                 &digestBuf,
                                 digestBuf.count,
                                 signBuf,
                                 signBuf.count)
        
        if status == errSecSuccess {
            return true
        } else {
            return false
        }
        
    }
    
    
}

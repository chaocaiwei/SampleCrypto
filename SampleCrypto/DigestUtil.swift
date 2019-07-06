//
//  DigestUtil.swift
//  SampleCrypto
//
//  Created by myself on 2019/7/5.
//  Copyright © 2019 chaocaiwei. All rights reserved.
//

import UIKit
import CommonCrypto

// 散列函数加密
class DigestUtil {
    
    static func md5(data:Data)->Data{
        var srcBuf = [UInt8](data)
        var outLen =  Int(CC_MD5_DIGEST_LENGTH)
        let outBuf = UnsafeMutablePointer<UInt8>.allocate(capacity:Int(outLen))
        defer { outBuf.deallocate() }
        CC_MD5(&srcBuf,CC_LONG(data.count),outBuf)
        return  Data(UnsafeBufferPointer(start:outBuf, count:outLen))
    }
    
    static func sha1(data:Data)->Data{
        var srcBuf = [UInt8](data)
        var outLen =  Int(CC_SHA1_DIGEST_LENGTH)
        let outBuf = UnsafeMutablePointer<UInt8>.allocate(capacity:Int(outLen))
        defer { outBuf.deallocate() }
        CC_SHA1(&srcBuf,CC_LONG(data.count),outBuf)
        return  Data(UnsafeBufferPointer(start:outBuf, count:outLen))
    }
    
    static func sha224(data:Data)->Data{
        var srcBuf = [UInt8](data)
        var outLen =  Int(CC_SHA224_DIGEST_LENGTH)
        let outBuf = UnsafeMutablePointer<UInt8>.allocate(capacity:Int(outLen))
        defer { outBuf.deallocate() }
        CC_SHA224(&srcBuf,CC_LONG(data.count),outBuf)
        return  Data(UnsafeBufferPointer(start:outBuf, count:outLen))
    }
    
    static func sha256(data:Data)->Data{
        var srcBuf = [UInt8](data)
        var outLen =  Int(CC_SHA256_DIGEST_LENGTH)
        let outBuf = UnsafeMutablePointer<UInt8>.allocate(capacity:Int(outLen))
        defer { outBuf.deallocate() }
        CC_SHA256(&srcBuf,CC_LONG(data.count),outBuf)
        return  Data(UnsafeBufferPointer(start:outBuf, count:outLen))
    }
    
    static func sha384(data:Data)->Data{
        var srcBuf = [UInt8](data)
        var outLen =  Int(CC_SHA384_DIGEST_LENGTH)
        let outBuf = UnsafeMutablePointer<UInt8>.allocate(capacity:Int(outLen))
        defer { outBuf.deallocate() }
        CC_SHA384(&srcBuf,CC_LONG(data.count),outBuf)
        return  Data(UnsafeBufferPointer(start:outBuf, count:outLen))
    }
    
    static func sha512(data:Data)->Data{
        var srcBuf = [UInt8](data)
        var outLen =  Int(CC_SHA512_DIGEST_LENGTH)
        let outBuf = UnsafeMutablePointer<UInt8>.allocate(capacity:Int(outLen))
        defer { outBuf.deallocate() }
        CC_SHA512(&srcBuf,CC_LONG(data.count),outBuf)
        return  Data(UnsafeBufferPointer(start:outBuf, count:outLen))
    }
    
}

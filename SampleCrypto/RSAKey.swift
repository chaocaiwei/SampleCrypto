//
//  RSAKeyUtil.swift
//  SampleCrypto
//
//  Created by myself on 2019/7/4.
//  Copyright © 2019 chaocaiwei. All rights reserved.
//

import UIKit

final class RSAKey {
    
    enum KeyType {
        case `public`
        case `private`
    }
    
    let type : KeyType
    let reference: SecKey
    var originalData: Data?
    
    var asn1 : ASN1Object?
    var n : Data?
    var e : Data?
    
    var version : Int?
    var d : Data?
    var p : Data?
    var q : Data?
    
    init(type:KeyType,reference:SecKey) {
        self.type = type
        self.reference = reference
        if self.originalData == nil {
            self.originalData = RSAKey.outputData(withKey:reference)
        }
        setupAllValues()
    }
    
    convenience init?(pemPath:String) {
        guard let data = try? Data(contentsOf: URL(fileURLWithPath:pemPath)),
            let pemString = String(data:data, encoding:.utf8) else {
            return nil
        }
        
        // 去掉开始结束标识以及回车符
        let base64String = pemString.components(separatedBy:"\n").filter({
            !$0.contains("BEGIN") && !$0.contains("END")
        }).joined()
        
        // base64解码
        guard let contentData = Data(base64Encoded: base64String, options: [.ignoreUnknownCharacters]) else {
            return nil
        }
        
        
        let type : KeyType = pemString.contains("PUBLIC") ? .public : .private
        self.init(data: contentData,type: type)
        
    }
    
    convenience init?(p12Path:String,pwd:String?=nil) {
        guard let data = try? Data(contentsOf: URL(fileURLWithPath:p12Path)) else {
            return nil
        }
        
        var item = CFArrayCreate(nil, nil, 0,nil)
        let options = pwd != nil ? [kSecImportExportPassphrase:pwd] : [:]
        let status = SecPKCS12Import(data as CFData,options as CFDictionary,&item)
        if status != noErr {
            return nil
        }
        
        guard  let itemArr = item as? [Any],
            let dict = itemArr.first as? [String:Any],
            let secIdentity = dict[kSecImportItemIdentity as String]   else{
            return nil
        }
        
        let secIdentityRef = secIdentity as! SecIdentity
        var keyRef : SecKey?
        SecIdentityCopyPrivateKey(secIdentityRef,&keyRef)
        guard let key = keyRef else {
            return nil
        }
        
        /* 由证书导出的公钥和由私钥导出的公钥是一样的
        if let trust = dict[kSecImportItemTrust as String] {
            let trustRef = trust as! SecTrust
            let pubKey = SecTrustCopyPublicKey(trustRef)
            let pubKey1 = SecKeyCopyPublicKey(key)
            print(pubKey)
            print(pubKey1)
        }
         let cer = dict["chain"] as! SecCertificate
        */
        
        
        
        self.init(type:KeyType.private,reference:key)
        
    }
    
    static func stripKeyHeader(data:Data)->Data?{
        guard  let ans = try? ASN1DERDecoder.decode(data:data).first,
            let subs = ans.sub else {
            return nil
        }
        
        // 判断是否都是整形数据
        var isAllIntObj = true
        for sub in subs {
            if sub.identifier?.tagNumber() != .some(.integer) {
                isAllIntObj = false
                break
            }
        }
        
        // 去掉外层的其他数据
        if !isAllIntObj {
            if let last = ans.sub?.last ,last.identifier?.tagNumber() == .some(.bitString) {
                return last.value as? Data
            }else{
                return nil
            }
        }else {
            return data
        }
    }
    
    init?(data:Data,type:KeyType) {
        
        guard let data = RSAKey.stripKeyHeader(data: data) else {
            return nil
        }
        
        let keyClass = type == .public ? kSecAttrKeyClassPublic : kSecAttrKeyClassPrivate
        let sizeInBits = data.count * 8
        let keyDict: [CFString: Any] = [
            kSecAttrKeyType: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass: keyClass,
            kSecAttrKeySizeInBits: NSNumber(value: sizeInBits),
            kSecReturnPersistentRef: true
        ]
        
        var error: Unmanaged<CFError>?
        guard let key = SecKeyCreateWithData(data as CFData, keyDict as CFDictionary, &error) else {
            print(error?.takeRetainedValue() ?? "unkown error")
            return nil
        }
        self.originalData = data
        self.type = type
        self.reference = key
        setupAllValues()
    }
    
    private func setupAllValues(){
        if let data = self.originalData {
            do {
               let asn1 = try ASN1DERDecoder.decode(data:data).first
               self.asn1 = asn1
                if self.type == .private {
                    setupPrivateKey()
                }else{
                    setupPubliKey()
                }
            }catch {
                print(error.localizedDescription)
            }
        }
    }
    
    private func setupPubliKey(){
        let subs = self.asn1?.sub
        let sub1 = subs?[0]
        if sub1?.identifier?.isConstructed() == false  {
            self.n = sub1?.value as? Data
            self.e = subs?[1].value as? Data
        }else{
            
        }
    }
    
    private func setupPrivateKey(){
        let subs = self.asn1?.sub
        self.version = Int(subs?[0].rawValue?[0] ?? 0)
        self.n = subs?[1].value as? Data
        self.e = subs?[2].value as? Data
        self.d = subs?[3].value as? Data
        self.p = subs?[4].value as? Data
        self.q = subs?[5].value as? Data
    }
    
    
    
    static func gennerateKeyPair(size:Int)->(privateKey:RSAKey?, publicKey:RSAKey?){
        let attributes: [CFString: Any] = [
            kSecAttrKeyType: kSecAttrKeyTypeRSA,
            kSecAttrKeySizeInBits: size,
        ]
        var error: Unmanaged<CFError>?
        if let privKeyRef = SecKeyCreateRandomKey(attributes as CFDictionary,&error)  {
            let privKey = RSAKey(type:.private, reference:privKeyRef)
            let pubKey  = privKey.publicKey
            return (privKey,pubKey)
        }else{
            print(error?.takeRetainedValue() ?? "unkown error")
            return (nil,nil)
        }
    }
    
    var publicKey : RSAKey?{
        guard let pubKeyRef = SecKeyCopyPublicKey(self.reference) else {
            return  nil
        }
        let pubKey = RSAKey(type:.public, reference:pubKeyRef)
        return pubKey
    }
    
    static func outputData(withKey reference:SecKey)->Data?{
        var error: Unmanaged<CFError>?
        let data = SecKeyCopyExternalRepresentation(reference, &error)
        return data as Data?
    }
    
    
}

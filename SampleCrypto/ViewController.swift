//
//  ViewController.swift
//  SampleCrypto
//
//  Created by myself on 2019/5/27.
//  Copyright © 2019 chaocaiwei. All rights reserved.
//

import UIKit

let kPfxPwd = "720083"

class ViewController: UIViewController {
    
    override func viewDidLoad() {
        super.viewDidLoad()
        testRSAEncrypt()
        testRSASignAnyVeryfy()
    }
    
    func testRSASignAnyVeryfy(){
        let text = """
        此次 Xcode 11 的更新，总体来说还是有不少让人兴奋的新特性的，了解这些新特性也对我们日常工作会有很大帮助，我们首先来整体看看都有哪些主要我们大概率会用得到的特性：

        Xcode 11 中重新设计了 Assistant Editor 和 Version Editor 的使用方式，将这两个 Editor 切换按钮从最上层的工具栏中移除，使用起来更人性化一些。
        原本在 Xcode 中，我们最多只能同时在一个屏幕中看两个文件的代码，现在利用 Xcode 11 中的分屏功能，我们可以任意在同一屏幕中拆分出不同的部分来看代码，借用喵神的话说就是："大屏用户的福音！想不到 Xcode 也能有今天"
        Xcode 11 拥有了和 Sublime、Visual Studio Code 一样的 Source Minimap 了，并且在功能上要青出于蓝而胜于蓝
        Xcode 11 集成了对 Swift Package Manager (SPM) 的支持，并且，全平台可用！
        Xcode 11 丰富了对于 git 的支持，例如我们现在可以在 Xcode 中执行 cherry-pick 了
        Xcode 11 中的 StoryBoard 的编辑页面中，增加了对 Dark Mode 的 UI 的预览功能
        当我们想测试 App 在弱网条件下的表现时，我们无需再借助开发者选项或者 Xcode 的 Additional Tools，可以直接在 Xcode 11 中设置
        Xcode 11 提供的模拟器改成基于 Metal 构建后性能大大提升。同时得益于 watchOS 的升级，开启 watch 的模拟器的时候不需要先打开一个 iPhone 的模拟器了。
        以上是本次 Session 的一个概览，更多的细节，我们将会根据 Session 的分类，在如下几个小节中仔细过一遍：
        """
        let pubKey = self.getPublicKeyFromPem()
        let privKey = self.getPrivateKeyFromPem()
        let signText = RSACryptoUtil.sign(string:text, key:privKey, digestType:.sha512)
        let signText1 = RSACryptoUtil.sign(string:text, key:privKey, digestType:.sha512)
        print("两次签名 \(signText == signText1 ? "一样": "不一样")")
        let isV = RSACryptoUtil.verify(string:text, sign:signText!, key:pubKey, digest:.sha512)
        print("rsa encrypt and decrypt \(isV ? "pass" : "fail")")
        // 签名的长度都是172个字符
    }
    
    func testRSAEncrypt(){
        var text = """
        此次 Xcode 11 的更新，总体来说还是有不少让人兴奋的新特性的，了解这些新特性也对我们日常工作会有很大帮助，我们首先来整体看看都有哪些主要我们大概率会用得到的特性：

        Xcode 11 中重新设计了 Assistant Editor 和 Version Editor 的使用方式，将这两个 Editor 切换按钮从最上层的工具栏中移除，使用起来更人性化一些。
        原本在 Xcode 中，我们最多只能同时在一个屏幕中看两个文件的代码，现在利用 Xcode 11 中的分屏功能，我们可以任意在同一屏幕中拆分出不同的部分来看代码，借用喵神的话说就是："大屏用户的福音！想不到 Xcode 也能有今天"
        Xcode 11 拥有了和 Sublime、Visual Studio Code 一样的 Source Minimap 了，并且在功能上要青出于蓝而胜于蓝
        Xcode 11 集成了对 Swift Package Manager (SPM) 的支持，并且，全平台可用！
        Xcode 11 丰富了对于 git 的支持，例如我们现在可以在 Xcode 中执行 cherry-pick 了
        Xcode 11 中的 StoryBoard 的编辑页面中，增加了对 Dark Mode 的 UI 的预览功能
        当我们想测试 App 在弱网条件下的表现时，我们无需再借助开发者选项或者 Xcode 的 Additional Tools，可以直接在 Xcode 11 中设置
        Xcode 11 提供的模拟器改成基于 Metal 构建后性能大大提升。同时得益于 watchOS 的升级，开启 watch 的模拟器的时候不需要先打开一个 iPhone 的模拟器了。
        以上是本次 Session 的一个概览，更多的细节，我们将会根据 Session 的分类，在如下几个小节中仔细过一遍：
        """
        text = [text,text,text,"fdhasjgyj324",text,text].joined()
        let pubKey = self.getPublicKeyFromPem()
        let encryptText = RSACryptoUtil.encrypt(string:text, key:pubKey)
        let encryptText1 = RSACryptoUtil.encrypt(string:text, key:pubKey)
        print("两次加密 \(encryptText == encryptText1 ? "一样": "不一样")")
        let privKey = self.getPrivateKeyFromPem()
        let decryptText = RSACryptoUtil.decrypt(string:encryptText!, key:privKey)
        let decryptText1 = RSACryptoUtil.decrypt(string:encryptText1!, key:privKey)
        print("rsa encrypt and decrypt \(decryptText == text ? "pass" : "fail")")
        print("两次解密 \(decryptText == decryptText1 ? "一样": "不一样")")
    }
    
    func getPublicKeyFromPem()->RSAKey{
        let pubPath = Bundle.main.path(forResource:"public-key-1024.pem", ofType:nil)!
        let pubKey = RSAKey(pemPath:pubPath)
        return pubKey!
    }
    
    func getPrivateKeyFromPem()->RSAKey{
        let privPath = Bundle.main.path(forResource:"private-key-1024.pem", ofType:nil)!
        let privKey = RSAKey(pemPath:privPath)
        return privKey!
    }
    
    func testInportKey(){
        
    
        print(self.getPublicKeyFromPem())
        print(self.getPrivateKeyFromPem())
        
        let p12Path = Bundle.main.path(forResource:"tl_dis.p12", ofType:nil)!
        let p12key  = RSAKey(p12Path:p12Path, pwd:"123456")
        print(p12key?.reference ?? "nil")
        
    }
    
    func testGenerateKey(){
        let keyPair = RSAKey.gennerateKeyPair(size:1024)
        print(keyPair.publicKey?.originalData?.hexString ?? "nil")
        print(keyPair.privateKey?.originalData?.hexString ?? "nil")
    }
    
    
    private func printPbKey()
    {
        // 32位模长公钥
        let publicKey = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCgKb/QOPzru7qpCZB8NOub2GFzEdEoSTm4Q+HCHqKHIBlc8VCIsmPA1StoiFJ1zdgmurQwaeCk6eA9z79np5ixviBBc1vm8HqSQRtiV0dgJb47de1GDmFSA6UAWRw8lNKUFrwIbU+6hsb80jx5xJkXr/lcmVDnKCpC2ccuuhecIwIDAQAB"
        let privateKey = "MIICXAIBAAKBgQCgKb/QOPzru7qpCZB8NOub2GFzEdEoSTm4Q+HCHqKHIBlc8VCIsmPA1StoiFJ1zdgmurQwaeCk6eA9z79np5ixviBBc1vm8HqSQRtiV0dgJb47de1GDmFSA6UAWRw8lNKUFrwIbU+6hsb80jx5xJkXr/lcmVDnKCpC2ccuuhecIwIDAQABAoGAeWnMt7tLuCQyx0ux1QaFCTpJ/WInTUPdVptW+8IfcRHbSELCyy14Q0kVxAN7h0RJNGrah8zrd/i3fgQL1DcPn5LWMddPkKCOBxr3DXkl9hoKg2sAM70yLLPdcWS1+MyfIcOBrauwH5IL7Yh2bJXG4ucoJMqghcdpwlaiTXBLWekCQQDVXyfGhPQ32qgQKA8zjwXnqNMJf8px/oaglbMhMLi0zyeJIeptza80L207ZNZBhXQQ0WMpqvJ5wEvtLPl7fEMPAkEAwClAepYyifeXvXajbOobfaQj4z1OCBohEEiB7SkBxa66uV+YVfQknLAUl940B01eU1trwk3Nr0benbgG/UEFrQJARhYeg5fyfFJHeB8gdygYoXKT93/RaMZZRHBHybQuR73v15ybW3v/e93EPIkv04/Zgxi0QOCVCyb+CacHP+eeQwJBAJlsFjwJ0X4QPYmawG6EF8DfnXugBb44Rm++xGV62RxhHlpE9dain9yuRTLfyUCPSCFbm5S+E9u+xJy+Qm5PTN0CQGoeGykvAfHrlOB5/gD3wu3mGH62rwKi2RVFhhv+89B9Ij1k1BAQtIAIiroGcZ86ciPWKGsXYFc6WmxpNsoGVlo="
        
        let pbData = Data(base64Encoded:publicKey)!
        print(pbData.hexString)
        print("pbData.lenght=\(pbData.count)")
        let ret = try? ASN1DERDecoder.decode(data:pbData)
        print("pbData ASN1Parse \(ret?.description ?? "nil")")
        
        let priData = Data(base64Encoded:privateKey)
        print(priData?.hexString ?? "pbData nil")
        print("pbData.lenght=\(priData?.count ?? 0)")
        print("private asn1=\(try! ASN1DERDecoder.decode(data:priData!))")
        
    }

}


//
//  Data+Bit.swift
//  SampleCrypto
//
//  Created by myself on 2019/7/2.
//  Copyright © 2019 chaocaiwei. All rights reserved.
//

import UIKit

extension UInt8 {
    var hexString : String {
        let str = String(format:"0x%02x",self)
        return str
    }
}

extension Data : CustomStringConvertible{
    var bytes : [UInt8] {
        return [UInt8](self)
    }
    var hexString : String {
        var str = ""
        for byte in self.bytes {
            str += byte.hexString
            str += " "
        }
        return str
    }
    
     var description: String {
        return "\(self.hexString)"
    }
    
}


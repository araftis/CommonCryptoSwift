/*
 Data+Extensions.swift
 Copyright (c) 2021, AJ Raftis <araftis@calpoly.edu>
 All rights reserved.

 Redistribution and use in source and binary forms, with or without
 modification, are permitted provided that the following conditions are met:
 * Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
 * Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
 * Neither the name of the AJ Raftis nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.

 THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL AJ RAFTIS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

import Foundation
import CommonCryptoSwift

func ccConditionalData(_ inputText: String?) -> Data? {
    if let inputText = inputText {
        return Data(hexString: inputText)
    }
    return nil
}

func multiCrypt(op: Cryptor.Operation,
                alg: Cryptor.Algorithm,
                options: Cryptor.Options,
                key: Data,
                iv: Data?,
                dataIn: Data,
                dataOut: inout Data) throws -> Int {
    var p1 : Int
    var p2 : Int
    var newmoved : Int = 0
    var finalSize : Int
    var dataInOffset = 0
    var dataOutOffset = 0
    var dataOutAvailable = dataOut.count

    let cref = try Cryptor(operation: op, algorithm: alg, options: options, key: key, initializationVector: iv)

    if dataIn.count < 16 {
        p1 = 0
    } else {
        p1 = (dataIn.count / 16) * 16 - 1
    }
    if p1 > 16 {
        p1 = dataIn.count
    }
    p2 = dataIn.count - p1

    var dataOutMoved = 0

    if p1 != 0 {
        dataOutMoved = try cref.update(dataIn: dataIn[dataInOffset ..< dataInOffset + p1], dataOut: &dataOut[dataOutOffset ..< dataOutAvailable])
        dataInOffset += p1
        dataOutOffset += dataOutMoved
        dataOutAvailable -= dataOutMoved
    }
    if p2 != 0 {
        newmoved = try cref.update(dataIn: dataIn[dataInOffset ..< dataInOffset + p2], dataOut: &dataOut[dataOutOffset ..< dataOutAvailable])
        dataOutOffset += newmoved;
        dataOutAvailable -= newmoved
        dataOutMoved += newmoved
    }

    /* We've had reports that Final fails on some platforms if it's only cipher blocksize.  */
    switch alg {
    case .des: fallthrough
    case .threeDES: finalSize = Cryptor.BlockSize.threeDES.rawValue
    case .aes: finalSize = Cryptor.BlockSize.aes128.rawValue
    case .cast: finalSize = Cryptor.BlockSize.cast.rawValue
    case .rc2: finalSize = Cryptor.BlockSize.rc2.rawValue
    default: finalSize = dataOutAvailable
    }

    newmoved = try cref.final(dataOut: &dataOut[dataOutOffset ..< dataOutOffset + finalSize])
    try cref.release()
    dataOutMoved += newmoved
    return dataOutMoved
}

func cryptTest(keyStr: String,
               ivStr: String?,
               alg: Cryptor.Algorithm,
               options: Cryptor.Options,
               cipherText: String?,
               plainText: String?,
               log: Bool = false) throws -> Bool {
    var key: Data
    var iv: Data? = nil
    var pt: Data? = nil
    var ct: Data? = nil
    var bb: Data? = nil
    var bb2: Data? = nil
    var dataWritten = 0

    //CCCryptorStatus retval;
    var cipherDataOut: Data = Data(repeating: 0, count: 4096)
    var plainDataOut: Data = Data(repeating: 0, count: 4096)


    key = Data(hexString: keyStr)!
    pt = ccConditionalData(plainText)
    ct = ccConditionalData(cipherText)
    iv = ccConditionalData(ivStr);

    if alg == .aes {
        do {
            dataWritten = try Cryptor.crypt(operation: .encrypt, algorithm: alg, options: options, key: key, initializationVector: iv, dataIn: pt!, dataOut: &cipherDataOut)
        } catch is Cryptor.Error {
            return false
        }
    }

    do {
        dataWritten = try Cryptor.crypt(operation: .encrypt, algorithm: alg, options: options, key: key, initializationVector: iv, dataIn: pt!, dataOut: &cipherDataOut)
        cipherDataOut.count = dataWritten
    } catch {
        if log {
            NSLog("Encrypt Failed \(error)")
        }
        return false
    }

    bb = cipherDataOut // bytesToBytes(cipherDataOut, dataOutMoved);

    // If ct isn't defined we're gathering data - print the ciphertext result
    if ct == nil {
        if log {
            NSLog("Input Length \(pt!.count) Result: \(bb!.hexString)")
        }
    } else {
        if ct != bb {
            if log {
                NSLog("FAIL Encrypt Output \(bb!.hexString)\nEncrypt Expect \(ct!.hexString)")
            }
            return false
        }
    }

    do {
        dataWritten = try Cryptor.crypt(operation: .decrypt, algorithm: alg, options: options, key: key, initializationVector: iv, dataIn: cipherDataOut, dataOut: &plainDataOut)
        plainDataOut.count = dataWritten
    } catch {
        if log {
            NSLog("Decrypt Failed: \(error)")
        }
        return false
    }

    bb2 = plainDataOut //bytesToBytes(plainDataOut, dataOutMoved);

    if pt != bb2 {
        if log {
            NSLog("FAIL Decrypt Output \(bb!.hexString)\nDecrypt Expect \(pt!.hexString)")
        }
        return false
    }

    return true
}

func multiCryptTest(keyStr: String,
                    ivStr: String?,
                    alg: Cryptor.Algorithm,
                    options: Cryptor.Options,
                    cipherText: String?,
                    plainText: String?) -> Bool {
    var key: Data
    var iv: Data? = nil
    var pt: Data? = nil
    var ct: Data? = nil
    var bb: Data? = nil
    var cipherDataOut = Data(repeating: 0, count: 4096)
    var plainDataOut = Data(repeating: 0, count: 4096)
    var dataOutMoved : Int

    key = Data(hexString: keyStr)!
    pt = ccConditionalData(plainText)
    ct = ccConditionalData(cipherText)
    iv = ccConditionalData(ivStr)

    do {
        dataOutMoved = try multiCrypt(op: .encrypt, alg: alg, options: options, key: key, iv: iv, dataIn: pt!, dataOut: &cipherDataOut)
        cipherDataOut.count = dataOutMoved
    } catch {
        return false
    }

    bb = cipherDataOut

    // If ct isn't defined we're gathering data - print the ciphertext result
    if ct == nil {
        NSLog("Input Length \(pt!.count) Result: \(bb!.hexString)")
    } else {
        if ct != bb {
            NSLog("FAIL Encrypt Output \(bb!.hexString)\nEncrypt Expect \(ct!.hexString)\n")
            return false
        }
    }

    do {
        dataOutMoved = try multiCrypt(op: .decrypt, alg: alg, options: options, key: key, iv: iv, dataIn: cipherDataOut, dataOut: &plainDataOut)
        plainDataOut.count = dataOutMoved
    } catch {
        NSLog("Decrypt Failed");
        return false
    }

    bb = plainDataOut

    if pt != bb {
        NSLog("FAIL Decrypt Output \(bb!.hexString)\nDecrypt Expect \(pt!.hexString)")
        return false
    }

    return true
}


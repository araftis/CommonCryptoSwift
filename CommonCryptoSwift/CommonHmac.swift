/*
 CommonHmac.swift
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
import CommonCrypto

/**
 Algorithms implemented in this module.
 */
public enum HmacAlgorithm : UInt32 {
    /// HMAC with SHA1 digest
    case sha1 = 0   // kCCHmacAlgSHA1
    /// HMAC with MD5 digest
    case md5 = 1    // kCCHmacAlgMD5
    /// HMAC with SHA256 digest
    case sha256 = 2 // kCCHmacAlgSHA256
    /// HMAC with SHA384 digest
    case sha384 = 3 // kCCHmacAlgSHA384
    /// HMAC with SHA512 digest
    case sha512 = 4 // kCCHmacAlgSHA512
    /// HMAC with SHA224 digest
    case sha224 = 5 // kCCHmacAlgSHA224

    public var digestLength : Int {
        switch self {
        case .md5:    return Int(CC_MD5_DIGEST_LENGTH) // To avoid the deprecation error.
        case .sha1:   return SHA1.digestLength
        case .sha224: return SHA224.digestLength
        case .sha256: return SHA256.digestLength
        case .sha384: return SHA384.digestLength
        case .sha512: return SHA512.digestLength
        }
    }
}

public struct Hmac {

    public static let digestLength = Int(CC_SHA256_DIGEST_LENGTH)
    public static let blockBytes = Int(CC_SHA256_BLOCK_BYTES)

    private var context = UnsafeMutablePointer<CCHmacContext>.allocate(capacity: 1)
    private var algorithm : HmacAlgorithm

    /**
     Create a new Hmac with provided raw key bytes.

     - parameter algorithm: HMAC algorithm to perform.
     - parameter key: Key bytes.
     */
    public init?(algorithm: HmacAlgorithm, key: Data?) {
        self.algorithm = algorithm
        Cryptor.dataWithUnsafeBytes(key) { (keyBytes, keyLength) -> Void in
            CCHmacInit(context, algorithm.rawValue, keyBytes, keyLength)
        }
    }

    /**
     Process some data.

     - parameter data: Data to process.

     This can be called multiple times.
     */
    public func update(data: Data) -> Void {
        return Cryptor.dataWithUnsafeBytes(data) { (dataBytes, dataLength) -> Void in
            CCHmacUpdate(context, dataBytes, Int(dataLength))
        }
    }

    /**
     Obtain the final Message Authentication Code.

     Note: This may contain an issue with Swift in that when comparing Macs, you'd normally need to use `timingsafe_bcmp()`, but that's not readily available.
     */
    public func final() -> Data {
        var macOut = [UInt8](repeating: 0, count: algorithm.digestLength)
        CCHmacFinal(context, &macOut)
        return Data(macOut)
    }

    /**
     Stateless, one-shot HMAC function

     - parameter algorithm: HMAC algorithm to perform.
     - parameter key: Key bytes.
     - parameter data: Data to process.

     The MAC must be verified by comparing the computed and expected values using timingsafe_bcmp. Other comparison functions (e.g. memcmp) must not be used as they may be vulnerable to practical timing attacks, leading to MAC forgery.
    */
    public static func digest(algorithm: HmacAlgorithm, key: Data?, data : Data) -> Data {
        var macOut = [UInt8](repeating: 0, count: algorithm.digestLength)
        Cryptor.dataWithUnsafeBytes(key) { (keyBytes, keyLength) -> Void in
            Cryptor.dataWithUnsafeBytes(data) { (dataBytes, dataLength) -> Void in
                CCHmac(algorithm.rawValue, keyBytes, keyLength, dataBytes, dataLength, &macOut)
            }
        }
        return Data(macOut)
    }

}


/*
 CommonSymmeticKeywrap.swift
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

/// Defines the algorithm to use when wrapping keys. Currently only supports AES, as defined by [rfc3394](https://tools.ietf.org/html/rfc3394#section-2.2.3.1).
public enum WrappingAlgorithm : UInt32 {
    case aes = 1 // kCCWRAPAES
}

public extension IV {
    /// The standard initial value as defined by [rfc3394](https://tools.ietf.org/html/rfc3394#section-2.2.3.1).
    static let rfc3394 : IV = Data(bytes: CCrfc3394_iv, count: CCrfc3394_ivLen)
}

/**
 Wrap a symmetric key with a Key Encryption Key (KEK).

 - parameter algorithm: Currently only AES Keywrapping ([rfc3394](https://tools.ietf.org/html/rfc3394)) is available via `WrappingAlgorithm.aes`.
 - parameter initializationVector: The initialization value to be used.  Default value is `WrappingAlgorithm.aes`.
 - parameter kek: The Key Encryption Key to be used to wrap the raw key.
 - parameter rawKey: The raw key bytes to be wrapped.

 The algorithm chosen is determined by the algorithm parameter and the size of the key being wrapped (ie aes128 for 128 bit keys).

 - returns: The wrapped key.

 - throws: A CryptorError on error:
   * **paramError** can result from bad values for the kek, rawKey, and wrappedKey key data.
 */
public func SymmetricKeyWrap(algorithm: WrappingAlgorithm = .aes,
                             initializationVector: IV = IV.rfc3394,
                             kek: Data,
                             rawKey: Data) throws -> Data {
    var length = SymmetricWrappedSize(algorithm: algorithm, rawKeyLength: rawKey.count)
    return try Data(count: length) { (wrappedKey) in
        let result = Cryptor.dataWithUnsafeBytes(initializationVector) { (ivBytes, ivLength) -> Int32 in
            return Cryptor.dataWithUnsafeBytes(kek) { (kekBytes, kekLength) -> Int32 in
                return Cryptor.dataWithUnsafeBytes(rawKey) { (rawKeyBytes, rawKeyLength) -> Int32 in
                    return CCSymmetricKeyWrap(algorithm.rawValue,
                                              ivBytes?.bindMemory(to: UInt8.self, capacity: ivLength), ivLength,
                                              kekBytes?.bindMemory(to: UInt8.self, capacity: kekLength), kekLength,
                                              rawKeyBytes?.bindMemory(to: UInt8.self, capacity: rawKeyLength), rawKeyLength,
                                              &wrappedKey, &length)
                }
            }
        }
        if result != kCCSuccess {
            throw Cryptor.Error.from(result)
        }
    }
}

/**
 Unwrap a symmetric key with a Key Encryption Key (KEK).

 - parameter algorithm: Currently only AES Keywrapping ([rfc3394](https://tools.ietf.org/html/rfc3394)) is available via `WrappingAlgorithm.aes`.
 - parameter initializationVector: The initialization value to be used.  The default value is `IV.rfc3394` is available as a constant for the standard IV to use.
 - parameter kek: The Key Encryption Key to be used to unwrap the raw key.
 - parameter wrappedKey: The wrapped key bytes.

 The algorithm chosen is determined by the algorithm parameter and the size of the key being wrapped (ie aes128 for 128 bit keys).

 - returns: The unwrapped key.

 - throws: A CryptorError on error:
   * **paramError** can result from bad values for the kek, rawKey, and wrappedKey key data.
 */
public func SymmetricKeyUnwrap(algorithm: WrappingAlgorithm = .aes,
                               initializationVector: IV = IV.rfc3394,
                               kek: Data,
                               wrappedKey: Data) throws -> Data {
    var length = SymmetricUnwrappedSize(algorithm: algorithm, wrappedKeyLength: wrappedKey.count)
    return try Data(count: length) { (rawKey) in
        let result = Cryptor.dataWithUnsafeBytes(initializationVector) { (ivBytes, ivLength) -> Int32 in
            return Cryptor.dataWithUnsafeBytes(kek) { (kekBytes, kekLength) -> Int32 in
                return Cryptor.dataWithUnsafeBytes(wrappedKey) { (wrappedKeyBytes, wrappedKeyLength) -> Int32 in
                    return CCSymmetricKeyUnwrap(algorithm.rawValue,
                                                ivBytes?.bindMemory(to: UInt8.self, capacity: ivLength), ivLength,
                                                kekBytes?.bindMemory(to: UInt8.self, capacity: kekLength), kekLength,
                                                wrappedKeyBytes?.bindMemory(to: UInt8.self, capacity: wrappedKeyLength), wrappedKeyLength,
                                                &rawKey, &length)
                }
            }
        }
        if result != kCCSuccess {
            throw Cryptor.Error.from(result)
        }
    }
}

/**
 Determine the buffer size required to hold a key wrapped with `SymmetricKeyWrap()`.

 - parameter algorithm: Currently only AES Keywrapping ([rfc3394](https://tools.ietf.org/html/rfc3394)) is available via `WrappingAlgorithm.aes`.
 - parameter rawKeyLen: The length of the key in bytes.

 - returns: The length of the resulting wrapped key.
 */
public func SymmetricWrappedSize(algorithm: WrappingAlgorithm = .aes, rawKeyLength: Int) -> Int {
    return CCSymmetricWrappedSize(algorithm.rawValue, rawKeyLength)
}

/**
 Determine the buffer size required to hold a key unwrapped with  `SymmetricKeyWUnwrap()`.

 - parameter algorithm: Currently only AES Keywrapping ([rfc3394](https://tools.ietf.org/html/rfc3394)) is available via `WrappingAlgorithm.aes`
 - parameter wrappedKeyLength: The length of the wrapped key in bytes.

 - returns: The length of the resulting raw key.
 */
public func SymmetricUnwrappedSize(algorithm: WrappingAlgorithm = .aes, wrappedKeyLength: Int) -> Int {
    return CCSymmetricUnwrappedSize(algorithm.rawValue, wrappedKeyLength)
}

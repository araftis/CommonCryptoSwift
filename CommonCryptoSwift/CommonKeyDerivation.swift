/*
 CommonKeyDerivation.swift
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

public enum PBKDFAlgorithm : UInt32 {
    case pbkdf2 = 2 //kCCPBKDF2
}

public enum PseudoRandomAlgorithm : UInt32 {
    case hmacAlgSHA1   = 1 // kCCPRFHmacAlgSHA1
    case hmacAlgSHA224 = 2 // kCCPRFHmacAlgSHA224
    case hmacAlgSHA256 = 3 // kCCPRFHmacAlgSHA256
    case hmacAlgSHA384 = 4 // kCCPRFHmacAlgSHA384
    case hmacAlgSHA512 = 5 // kCCPRFHmacAlgSHA512
}

/**
 Derive a key from a text password/passphrase

 - parameter algorithm: Currently only PBKDFAlgorithm.pbkdf2 is available.
 - parameter password: The text password used as input to the derivation function.  The actual octets present in this string will be used with no additional processing.  It's extremely important that the same encoding and normalization be used each time this routine is called if the same key is  expected to be derived. To make this easier, the string is first decomposed to its canonical mapping, and then converted to UTF-8.
 - parameter salt: The salt byte values used as input to the derivation function. May be nil, but the result will be stronger if you provide a salt.
 - parameter pseudoRandomAlgorithm: The Pseudo Random Algorithm to use for the derivation iterations. The default is `hmacAlgSHA256`.
 - parameter rounds: The number of rounds of the Pseudo Random Algorithm to use. It cannot be zero. Default is 10000.
 - parameter keySize : The expected length of the derived key in bytes.

 The following values are used to designate the PRF:

 * hmacAlgSHA1
 * hmacAlgSHA224
 * hmacAlgSHA256
 * hmacAlgSHA384
 * hmacAlgSHA512

 - returns: The resulting derived key produced by the function. The space for this must be provided by the caller.

 - throws: `Cryptor.Error` can result from bad values for the password, salt,  and unwrapped key pointers as well as a bad value for the prf
         function.
 */
public func CCKeyDerivationPBKDF(_ password: String,
                                 for algorithm: PBKDFAlgorithm = .pbkdf2,
                                 salt: Data?,
                                 pseudoRandomAlgorithm prf: PseudoRandomAlgorithm = .hmacAlgSHA256,
                                 rounds: Int = 10000,
                                 keySize: Cryptor.KeySize) throws -> Data {
    let data = try Data(count: keySize.rawValue, using: { (buffer) in
        if let passwordData = password.decomposedStringWithCanonicalMapping.data(using: .utf8) {
            let result = Cryptor.dataWithUnsafeBytes(passwordData) { (passwordBytes, passwordLength) -> Int32 in
                return Cryptor.dataWithUnsafeBytes(salt) { (saltBytes, saltLength) -> Int32 in
                    return CCKeyDerivationPBKDF(algorithm.rawValue,
                                                passwordBytes!.bindMemory(to: Int8.self, capacity: passwordLength), passwordLength,
                                                saltBytes!.bindMemory(to: UInt8.self, capacity: saltLength), saltLength,
                                                prf.rawValue,
                                                UInt32(rounds),
                                                &buffer, keySize.rawValue)
                }
            }
            if result != kCCSuccess {
                throw Cryptor.Error.from(result)
            }
        } else {
            throw Cryptor.Error.invalidKeyError
        }
    })
    return data
}

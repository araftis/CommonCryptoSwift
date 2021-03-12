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
import CommonCrypto

public extension Data {

    /**
     Generates a test Data object where the values are (1 ... `length`) % 256.

     Basically, this makes it easy to visually evaluate the results of a test.

     - parameter count: The length of the data you want.

     - returns: The generated data object.
     */
    internal init(testDataOfCount count: Int, using block:((_ data: inout [UInt8]) -> Void)? = nil) {
        var buffer = [UInt8](repeating: 0, count: count)
        if let block = block {
            block(&buffer)
        } else {
            for index in 0 ..< count {
                buffer[index] = UInt8(index % 256)
            }
        }
        self.init(buffer)
    }

    /**
     Creates a data of the given length `count` and then calls `block` to initialize it.

     - parameter count: The length of the data you want.
     - parameter block: A block that will be called to initialize the data.
     - parameter buffer: An initialized buffer of length `count` you can initialize.

     - returns: The newly initialized data.
     */
    init(count: Int, using block:(_ buffer: inout [UInt8]) throws -> Void) rethrows {
        var buffer = [UInt8](repeating: 0, count: count)
        try block(&buffer)
        self.init(buffer)
        // Don't leave this around, because it will likely contain sensitive data.
        buffer.resetBytes(in: 0 ..< count)
    }

    /**
     Poor man's data dump, but somewhat useful for testing. Looks similar to something like `xxd`.
     */
    var dump : String {
        var string = "(\(self.count))"
        if self.count <= 16 {
            string += " "
        }
        let digits = Int(ceil(log(Double(self.count)) / log(16)))
        for index in self.startIndex ..< self.endIndex {
            let hex = String(self[index], radix: 16)
            if index % 16 == 0 && self.count > 16 {
                if index + startIndex >= 16 {
                    for subindex in index - 16 ..< index {
                        if subindex < self.count + self.startIndex {
                            var value = self[subindex]
                            if value < 32 || (value > 0x7E && value < 0xA0) {
                                value = 0x2E
                            }
                            string.append(Character(Unicode.Scalar(value)))
                        }
                    }
                }
                string += "\n\(String(format: "%0*x", digits, index)): "
            }
            string += (self[index] < 0x10 ? "0" : "") + hex + " "
        }

        let extra =  16 - (self.count - ((self.count / 16) * 16))
        for _ in 0 ..< extra % 16 {
            string.append("   ")
        }
        var startIndex = self.count - (16 - extra)
        if startIndex == self.count && self.count > 16 {
            startIndex -= 16
        }
        for index in startIndex ..< self.count {
            var value = self[self.startIndex + index]
            if value < 32 || (value > 0x7E && value < 0xA0) {
                value = UInt8(46)
            }
            string.append(Character(Unicode.Scalar(value)))
        }

        return string
    }

    /// Computes the size of the encrypted data. The data is aligned to 16 byte blocks + 1 block, since we're using pkcs-7 padding.
    internal var aesEncryptedSize : Int {
        return (self.count / 16) * 16 + 16
    }

    /**
     Encrypts the data using the provided `key` and `initializationVector` using AES-128 in CBC mode and PKCS-7 padding.

     - parameter key: The key. Since this is AES-128, the key should be 16 bytes. You can generate this with `Cryptor.randomKey(for: .aes)`.
     - parameter initializationVector: The initialization vector. If you don't provide this, you get a default, which is 16 zeros. If you want to provide one, you can generate one with `Cryptor.randomInitializationVector()`. Make sure you pass in the same vector to `aesDecryptedData(key:initializationVector:)`.

     - returns: The encrypted data. Note that due to the use of PKCS-7 padding, the output will be 16 (1 AES block) larger than the receiver.

     - throws: Rethrows any errors from `Cryptor`.
     */
    func aesEncryptedData(key: Data, initializationVector: IV = IV.default) throws -> Data {
        var output = Data(repeating: 0, count: self.aesEncryptedSize)

        let bytesWritten = try Cryptor.crypt(operation: .encrypt,
                                               algorithm: .aes,
                                               options: [.pkcs7Padding],
                                               key: key,
                                               initializationVector: initializationVector,
                                               dataIn: self,
                                               dataOut: &output)
        output.count = bytesWritten

        return output
    }

    /**
     Encrypts the data using the provided password, salt, and initializationVector.

     - parameter password: The password you'd like to use. The password should be &lt; 16 characters long, or it will be truncated. It will also be padding out to 17 characters.
     - parameter salt: A salt to pseudo-randomize the password.
     - parameter initializationVector: The initialization vector. If you don't provide this, you get a default, which is 16 zeros. If you want to provide one, you can generate one with `Cryptor.randomInitializationVector()`. Make sure you pass in the same vector to `aesDecryptedData(password:salt:initializationVector:)`.

     - returns: The encrypted data. Note that due to the use of PKCS-7 padding, the output will be 16 (1 AES block) larger than the receiver.

     - throws: Rethrows any errors from `Cryptor`.
     */
    func aesEncryptedData(password: String, salt: Data, initializationVector: IV = IV.default) throws -> Data {
        return try aesEncryptedData(key: CCKeyDerivationPBKDF(password, salt: salt, keySize: .aes128), initializationVector: initializationVector)
    }

    /**
     Descrypts the receiver, which must contain AES-128 encrypted data.

     Generally speaking, this is the flip side of calling `aesEncryptedData(key:initializationVector:)`.

     - parameter key: The key. Since this is AES-128, the key should be 16 bytes. You can generate this with `Cryptor.randomKey(for: .aes)`.
     - parameter initializationVector: The initialization vector. If you don't provide this, you get a default, which is 16 zeros. You need to pass in whatever vector was used to create the encrypted data.

     - returns: The encrypted data. Note that due to the use of PKCS-7 padding, the output will be between 16  and 31 bytes smaller than the receiver.

     - throws: Rethrows any errors from `Cryptor`.
     */
    func aesDecryptedData(key: Data, initializationVector: IV = IV.default) throws -> Data {
        var output = Data(repeating: 0, count: self.count)

        let bytesWritten = try Cryptor.crypt(operation: .decrypt, algorithm: .aes, options: [.pkcs7Padding], key: key, initializationVector: initializationVector, dataIn: self, dataOut: &output)
        output.count = bytesWritten

        return output
    }

    /**
     Descrypts the receiver, which must contain AES-128 encrypted data.

     Generally speaking, this is the flip side of calling `aesEncryptedData(key:initializationVector:)`.

     - parameter password: The password you'd like to use. The password should be &lt; 16 characters long, or it will be truncated. It will also be padding out to 17 characters.
     - parameter salt: A salt to pseudo-randomize the password. Make sure to use the same salt as used during encryption.
     - parameter initializationVector: The initialization vector. If you don't provide this, you get a default, which is 16 zeros. You need to pass in whatever vector was used to create the encrypted data.

     - returns: The encrypted data. Note that due to the use of PKCS-7 padding, the output will be between 16  and 31 bytes smaller than the receiver.

     - throws: Rethrows any errors from `Cryptor`.
     */
    func aesDecryptedData(password: String, salt: Data, initializationVector: IV = IV.default) throws -> Data {
        return try aesDecryptedData(key: CCKeyDerivationPBKDF(password, salt: salt, keySize: .aes128), initializationVector: initializationVector)
    }

    /**
     Converts an ASCII character `[0-9A-Fa-f]` to an unsigned integer 8 value in the range 0-15.

     - parameter nibble: In the input character to convert.

     - returns If the input character as an integer, or nil if the input is not in the correct range.
     */
    @inlinable
    internal static func hexNibbleToInt(_ nibble: UInt8) -> UInt8? {
        if nibble >= 65 && nibble <= 70 {
            return nibble - 55
        }
        if nibble >= 97 && nibble <= 102 {
            return nibble - 87
        }
        if nibble >= 48 && nibble <= 57 {
            return nibble - 48
        }
        return nil
    }

    /**
     Creates a new Data from the input string.

     - parameter hex: The string of hexidecimal characers to convert to Data.

     The string must be a valid hex string in that it only contains the characters `[0-9A-Fa-f]`, if any other characters are present, this will return nil. The input must also be evenly divisible by 2.
     */
    init?(hexString hex: String) {
        if let ascii = hex.data(using: .ascii) {
            let length = ascii.count
            if length % 2 != 0 {
                // We have to have two digits per
                return nil
            }
            var buffer = [UInt8](repeating: 0, count: length / 2)

            for index in stride(from: 0, to: length, by: 2) {
                if let hiNibble = Data.hexNibbleToInt(ascii[index]),
                   let loNibble = Data.hexNibbleToInt(ascii[index + 1]) {
                    buffer[index / 2] = hiNibble * 16 + loNibble
                } else {
                    return nil
                }
            }
            self.init(buffer)
        } else {
            return nil
        }
    }

    /**
     Converts a value in the range of 0-15 to it's corresponding ASCII value of '0'-'9' or 'A'-'F'.

     - parameter nibble: The value to convert to ASCII. Value must be 0-15

     - returns The nibble or nil if input nibble is out of range.
     */
    static internal func nibble<T:BinaryInteger>(_ nibble: T) -> T? {
        if nibble < 10 {
            return nibble + 48
        }
        if nibble < 16 {
            return nibble + 55
        }
        return nil
    }

    /**
     Returns a representation of the data as a hex encoding string. Always uses uppercase characters.

     This can be reversed by calling `Data(hexString:)`.
     */
    var hexString : String {
        var raw = Data(repeating: 0, count: count * 2)

        for (index, byte) in self.enumerated() {
            raw[index * 2 + 0] = Data.nibble((byte & 0xF0) >> 4)!
            raw[index * 2 + 1] = Data.nibble((byte & 0x0F) >> 0)!
        }

        return String(data: raw, encoding: .ascii)!
    }

    /**
     Generates cryptographically secure random data using Apple's security framework.

     - parameter length: How many bytes you want generated.

     - returns: The random data.

     - throws: `CryptorError.unknownError` if the data cannot be generated for some reason. This should be exceedingly rare.
     */
    init(randomDataOfLength length: Int) throws {
        try self.init(count: length) { (buffer) in
            let result = CCRandomGenerateBytes(&buffer, length)
            if result != kCCSuccess {
                throw Cryptor.Error.from(result)
            }
        }
    }

    /**
     Resizes the data to the given number of bits.

     - parameter count: The number of bits in the final output data.

     This is useful for some cryptographic work where you want to truncate something to a specific number of bits. As such, the length of the output will be `count / 8 + (count % 8 == 0 ? 0 : 1)` bytes long. The final byte, if there is a partial byte, will be masked off.

     */
    mutating func size(toBits count: Int) -> Void {
        let padCount = count % 8
        let byteCount = count / 8 + (padCount == 0 ? 0 : 1)

        self.count = byteCount

        if padCount != 0 {
            var padMask = UInt8(0)

            for _ in 0 ..< padCount {
                padMask <<= 1
                padMask &= 0x1
            }
            self[byteCount - 1] &= padMask
        }
    }

}

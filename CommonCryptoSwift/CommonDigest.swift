/*
 CommonDigest.swift
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
 Defines the protocol used to perform cryptographic hashes. Then using this protocol you have two options. You can use the one shot method:

 ```
 let hash = SHA256.digest(myData)
 ```

 or you can use the iterative form:

 ```
 let hasher = SHA256()

 for _ in stride(from: 0 to: 1024 by 256) {
    hasher.update(mySubdata)
 }

 let hash = hasher.final()
 ```

Many of the one shot methods are also available via conveniences on `Data` and `String`.
 */
public protocol CommonDigest {

    /// Digest length in bytes.
    static var digestLength : Int { get }
    /// Block size in bytes.
    static var blockBytes : Int { get }

    init?()
    func update(data: Data) -> Int
    func final() -> Data?
    static func digest(data: Data) -> Data

}

/**
 Implementation of M2 hashes. These are not longer considered cryptographically secure and should only be used for historical reasons. If you writing new software, use SHA256 or stronger.
 */
@available(macOS, introduced: 10.4, deprecated: 10.15, message: "This algorithm is cryptographically broken and should not be used in security contexts. Clients should migrate to SHA256 (or stronger).")
public struct MD2 : CommonDigest {

    public static let digestLength = Int(CC_MD2_DIGEST_LENGTH)
    public static let blockBytes = Int(CC_MD2_BLOCK_BYTES)

    private var context = UnsafeMutablePointer<CC_MD2_CTX>.allocate(capacity: 1)

    public init?() {
        if CC_MD2_Init(context) != 1 {
            return nil
        }
    }

    public func update(data: Data) -> Int {
        return Cryptor.dataWithUnsafeBytes(data) { (dataBytes, dataLength) -> Int in
            return Int(CC_MD2_Update(context, dataBytes, CC_LONG(dataLength)))
        }
    }

    public func final() -> Data? {
        var hash = [UInt8](repeating: 0, count: SHA1.digestLength)
        if CC_MD2_Final(&hash, context) == 1 {
            return Data(hash)
        }
        return nil
    }

    public static func digest(data : Data) -> Data {
        var hash = [UInt8](repeating: 0,  count: Int(digestLength))
        Cryptor.dataWithUnsafeBytes(data) { (dataBytes, dataLength) -> Void in
            _ = CC_MD2(dataBytes, CC_LONG(dataLength), &hash)
        }
        return Data(hash)
    }

}

/**
 Implementation of M4 hashes. These are not longer considered cryptographically secure and should only be used for historical reasons. If you writing new software, use SHA256 or stronger.
 */
@available(macOS, introduced: 10.4, deprecated: 10.15, message: "This algorithm is cryptographically broken and should not be used in security contexts. Clients should migrate to SHA256 (or stronger).")
public struct MD4 : CommonDigest {

    public static let digestLength = Int(CC_MD4_DIGEST_LENGTH)
    public static let blockBytes = Int(CC_MD4_BLOCK_BYTES)

    private var context = UnsafeMutablePointer<CC_MD4_CTX>.allocate(capacity: 1)

    public init?() {
        if CC_MD4_Init(context) != 1 {
            return nil
        }
    }

    public func update(data: Data) -> Int {
        return Cryptor.dataWithUnsafeBytes(data) { (dataBytes, dataLength) -> Int in
            return Int(CC_MD4_Update(context, dataBytes, CC_LONG(dataLength)))
        }
    }

    public func final() -> Data? {
        var hash = [UInt8](repeating: 0, count: SHA1.digestLength)
        if CC_MD4_Final(&hash, context) == 1 {
            return Data(hash)
        }
        return nil
    }

    public static func digest(data : Data) -> Data {
        var hash = [UInt8](repeating: 0,  count: Int(digestLength))
        Cryptor.dataWithUnsafeBytes(data) { (dataBytes, dataLength) -> Void in
            _ = CC_MD4(dataBytes, CC_LONG(dataLength), &hash)
        }
        return Data(hash)
    }

}

/**
 Implementation of M5 hashes. These are not longer considered cryptographically secure and should only be used for historical reasons. If you writing new software, use SHA256 or stronger.
 */
@available(macOS, introduced: 10.4, deprecated: 10.15, message: "This algorithm is cryptographically broken and should not be used in security contexts. Clients should migrate to SHA256 (or stronger).")
public struct MD5 : CommonDigest {

    public static let digestLength = Int(CC_MD5_DIGEST_LENGTH)
    public static let blockBytes = Int(CC_MD5_BLOCK_BYTES)

    private var context = UnsafeMutablePointer<CC_MD5_CTX>.allocate(capacity: 1)

    public init?() {
        if CC_MD5_Init(context) != 1 {
            return nil
        }
    }

    public func update(data: Data) -> Int {
        return Cryptor.dataWithUnsafeBytes(data) { (dataBytes, dataLength) -> Int in
            return Int(CC_MD5_Update(context, dataBytes, CC_LONG(dataLength)))
        }
    }

    public func final() -> Data? {
        var hash = [UInt8](repeating: 0, count: SHA1.digestLength)
        if CC_MD5_Final(&hash, context) == 1 {
            return Data(hash)
        }
        return nil
    }

    public static func digest(data : Data) -> Data {
        var hash = [UInt8](repeating: 0,  count: Int(digestLength))
        Cryptor.dataWithUnsafeBytes(data) { (dataBytes, dataLength) -> Void in
            _ = CC_MD5(dataBytes, CC_LONG(dataLength), &hash)
        }
        return Data(hash)
    }

}

/**
 Implementation of SHA1 hashes. These are not longer considered cryptographically secure and should only be used for historical reasons. If you writing new software, use SHA256 or stronger.
 */
public struct SHA1 : CommonDigest {

    public static let digestLength = Int(CC_SHA1_DIGEST_LENGTH)
    public static let blockBytes = Int(CC_SHA1_BLOCK_BYTES)

    private var context = UnsafeMutablePointer<CC_SHA1_CTX>.allocate(capacity: 1)

    public init?() {
        if CC_SHA1_Init(context) != 1 {
            return nil
        }
    }

    public func update(data: Data) -> Int {
        return Cryptor.dataWithUnsafeBytes(data) { (dataBytes, dataLength) -> Int in
            return Int(CC_SHA1_Update(context, dataBytes, CC_LONG(dataLength)))
        }
    }

    public func final() -> Data? {
        var hash = [UInt8](repeating: 0, count: SHA1.digestLength)
        if CC_SHA1_Final(&hash, context) == 1 {
            return Data(hash)
        }
        return nil
    }

    public static func digest(data : Data) -> Data {
        var hash = [UInt8](repeating: 0,  count: Int(digestLength))
        Cryptor.dataWithUnsafeBytes(data) { (dataBytes, dataLength) -> Void in
            _ = CC_SHA1(dataBytes, CC_LONG(dataLength), &hash)
        }
        return Data(hash)
    }

}

/**
 Implementation of SHA224 hashes.
 */
public struct SHA224 : CommonDigest {

    public static let digestLength = Int(CC_SHA224_DIGEST_LENGTH)
    public static let blockBytes = Int(CC_SHA224_BLOCK_BYTES)

    private var context = UnsafeMutablePointer<CC_SHA256_CTX>.allocate(capacity: 1)

    public init?() {
        if CC_SHA224_Init(context) != 1 {
            return nil
        }
    }

    public func update(data: Data) -> Int {
        return Cryptor.dataWithUnsafeBytes(data) { (dataBytes, dataLength) -> Int in
            return Int(CC_SHA224_Update(context, dataBytes, CC_LONG(dataLength)))
        }
    }

    public func final() -> Data? {
        var hash = [UInt8](repeating: 0, count: SHA224.digestLength)
        if CC_SHA224_Final(&hash, context) == 1 {
            return Data(hash)
        }
        return nil
    }

    public static func digest(data : Data) -> Data {
        var hash = [UInt8](repeating: 0,  count: Int(digestLength))
        Cryptor.dataWithUnsafeBytes(data) { (dataBytes, dataLength) -> Void in
            _ = CC_SHA224(dataBytes, CC_LONG(dataLength), &hash)
        }
        return Data(hash)
    }

}

/**
 Implementation of SHA256 hashes.
 */
public struct SHA256 : CommonDigest {

    public static let digestLength = Int(CC_SHA256_DIGEST_LENGTH)
    public static let blockBytes = Int(CC_SHA256_BLOCK_BYTES)

    private var context = UnsafeMutablePointer<CC_SHA256_CTX>.allocate(capacity: 1)

    public init?() {
        if CC_SHA256_Init(context) != 1 {
            return nil
        }
    }

    public func update(data: Data) -> Int {
        return Cryptor.dataWithUnsafeBytes(data) { (dataBytes, dataLength) -> Int in
            return Int(CC_SHA256_Update(context, dataBytes, CC_LONG(dataLength)))
        }
    }

    public func final() -> Data? {
        var hash = [UInt8](repeating: 0, count: SHA256.digestLength)
        if CC_SHA256_Final(&hash, context) == 1 {
            return Data(hash)
        }
        return nil
    }

    public static func digest(data : Data) -> Data {
        var hash = [UInt8](repeating: 0,  count: Int(digestLength))
        Cryptor.dataWithUnsafeBytes(data) { (dataBytes, dataLength) -> Void in
            _ = CC_SHA256(dataBytes, CC_LONG(dataLength), &hash)
        }
        return Data(hash)
    }

}

/**
 Implementation of SHA384 hashes.
 */
public struct SHA384 : CommonDigest {

    public static let digestLength = Int(CC_SHA384_DIGEST_LENGTH)
    public static let blockBytes = Int(CC_SHA384_BLOCK_BYTES)

    private var context = UnsafeMutablePointer<CC_SHA512_CTX>.allocate(capacity: 1)

    public init?() {
        if CC_SHA384_Init(context) != 1 {
            return nil
        }
    }

    public func update(data: Data) -> Int {
        return Cryptor.dataWithUnsafeBytes(data) { (dataBytes, dataLength) -> Int in
            return Int(CC_SHA384_Update(context, dataBytes, CC_LONG(dataLength)))
        }
    }

    public func final() -> Data? {
        var hash = [UInt8](repeating: 0, count: SHA384.digestLength)
        if CC_SHA384_Final(&hash, context) == 1 {
            return Data(hash)
        }
        return nil
    }

    public static func digest(data : Data) -> Data {
        var hash = [UInt8](repeating: 0,  count: Int(digestLength))
        Cryptor.dataWithUnsafeBytes(data) { (dataBytes, dataLength) -> Void in
            _ = CC_SHA384(dataBytes, CC_LONG(dataLength), &hash)
        }
        return Data(hash)
    }

}

/**
 Implementation of SHA512 hashes.
 */
public struct SHA512 : CommonDigest {

    public static let digestLength = Int(CC_SHA512_DIGEST_LENGTH)
    public static let blockBytes = Int(CC_SHA512_BLOCK_BYTES)

    private var context = UnsafeMutablePointer<CC_SHA512_CTX>.allocate(capacity: 1)

    public init?() {
        if CC_SHA512_Init(context) != 1 {
            return nil
        }
    }

    public func update(data: Data) -> Int {
        return Cryptor.dataWithUnsafeBytes(data) { (dataBytes, dataLength) -> Int in
            return Int(CC_SHA512_Update(context, dataBytes, CC_LONG(dataLength)))
        }
    }

    public func final() -> Data? {
        var hash = [UInt8](repeating: 0, count: SHA512.digestLength)
        if CC_SHA512_Final(&hash, context) == 1 {
            return Data(hash)
        }
        return nil
    }

    public static func digest(data : Data) -> Data {
        var hash = [UInt8](repeating: 0,  count: Int(digestLength))
        Cryptor.dataWithUnsafeBytes(data) { (dataBytes, dataLength) -> Void in
            _ = CC_SHA512(dataBytes, CC_LONG(dataLength), &hash)
        }
        return Data(hash)
    }

}

/**
 Conveniences on String for working with various hash algorithms.
 */
public extension Data {

    /// Returns the MD2 hash. Note this is deprecated, because MD2 is no longer considered cryptographically secure, but this is included because you may need to work with older software that makes use of MD2 hashes.
    @available(macOS, introduced: 10.4, deprecated: 10.15, message: "This algorithm is cryptographically broken and should not be used in security contexts. Clients should migrate to SHA256 (or stronger).")
    var md2 : Data { return MD2.digest(data: self) }
    /// Returns the MD4 hash. Note this is deprecated, because MD4 is no longer considered cryptographically secure, but this is included because you may need to work with older software that makes use of MD4 hashes.
    @available(macOS, introduced: 10.4, deprecated: 10.15, message: "This algorithm is cryptographically broken and should not be used in security contexts. Clients should migrate to SHA256 (or stronger).")
    var md4 : Data { return MD4.digest(data: self) }
    /// Returns the MD5 hash. Note this is deprecated, because MD5 is no longer considered cryptographically secure, but this is included because you may need to work with older software that makes use of MD5 hashes.
    @available(macOS, introduced: 10.4, deprecated: 10.15, message: "This algorithm is cryptographically broken and should not be used in security contexts. Clients should migrate to SHA256 (or stronger).")
    var md5 : Data { return MD5.digest(data: self) }
    /// Returns the SHA1 hash.
    var sha1 : Data { return SHA1.digest(data: self) }
    /// Returns the SHA224 hash.
    var sha224 : Data { return SHA224.digest(data: self) }
    /// Returns the SHA256 hash.
    var sha256 : Data { return SHA256.digest(data: self) }
    /// Returns the SHA384 hash.
    var sha384 : Data { return SHA384.digest(data: self) }
    /// Returns the SHA512 hash.
    var sha512 : Data { return SHA512.digest(data: self) }

}

/**
 Conveniences on String for working with various hash algorithms.
 */
public extension String {

    /**
     Converts the string to UTF-8 data and then call the requested hashing algorigthm.
     */
    internal func hash(using hasher: CommonDigest.Type) -> Data? {
        if let data = self.data(using: .utf8) {
            return hasher.digest(data: data)
        }
        return nil
    }

    /// Returns the MD2 hash. Note this is deprecated, because MD2 is no longer considered cryptographically secure, but this is included because you may need to work with older software that makes use of MD2 hashes.
    @available(macOS, introduced: 10.4, deprecated: 10.15, message: "This algorithm is cryptographically broken and should not be used in security contexts. Clients should migrate to SHA256 (or stronger).")
    var md2 : Data? { return hash(using: MD2.self) }
    /// Returns the MD4 hash. Note this is deprecated, because MD4is no longer considered cryptographically secure, but this is included because you may need to work with older software that makes use of MD4 hashes.
    @available(macOS, introduced: 10.4, deprecated: 10.15, message: "This algorithm is cryptographically broken and should not be used in security contexts. Clients should migrate to SHA256 (or stronger).")
    var md4 : Data? { return hash(using: MD4.self) }
    /// Returns the MD5 hash. Note this is deprecated, because MD5 is no longer considered cryptographically secure, but this is included because you may need to work with older software that makes use of MD5 hashes.
    @available(macOS, introduced: 10.4, deprecated: 10.15, message: "This algorithm is cryptographically broken and should not be used in security contexts. Clients should migrate to SHA256 (or stronger).")
    var md5 : Data? { return hash(using: MD5.self) }
    /// Returns the SHA1 hash.
    var sha1 : Data? { return hash(using: SHA1.self) }
    /// Returns the SHA224 hash.
    var sha224 : Data? { return hash(using: SHA224.self) }
    /// Returns the SHA256 hash.
    var sha256 : Data? { return hash(using: SHA256.self) }
    /// Returns the SHA384 hash.
    var sha384 : Data? { return hash(using: SHA384.self) }
    /// Returns the SHA512 hash.
    var sha512 : Data? { return hash(using: SHA512.self) }

}

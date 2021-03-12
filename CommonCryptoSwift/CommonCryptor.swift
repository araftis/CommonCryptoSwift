/*
 CommonCryptor.swift
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
 Generic interface for symmetric encryption.

 This interface provides access to a number of symmetric encryption algorithms. Symmetric encryption algorithms come in two "flavors" -  block ciphers, and stream ciphers. Block ciphers process data (while both encrypting and decrypting) in discrete chunks of  data called blocks; stream ciphers operate on arbitrary sized data.

 The object declared in this interface, Cryptor, provides access to both block ciphers and stream ciphers with the same API; however some options are available for block ciphers that do not apply to stream ciphers.

 The general operation of a Cryptor is: initialize it with raw key data and other optional fields with `Cryptor.init()`; process input data via one or more calls to `Cryptor.update()`, each of which may result in output data being written to caller-supplied memory; and obtain possible remaining output data with `Cryptor.final()`. When done, you can call `Cryptor.release()` to immediatley free and zero all memory used, or it can be reused (with the same key data as provided to `Cryptor.init()`) by calling `Cryptor.reset()`. The `Cryptor.reset()` function only works for the CBC mode. In other block cipher modes, it returns error.

 Cryptors can be dynamically allocated by this module, or their memory can be allocated by the caller. See discussion for `Cryptor.init()`  for information on Cryptor allocation.

 One option for block ciphers is padding, as defined in PKCS7; when padding is enabled, the total amount of data encrypted does not have to be an even multiple of the block size, and the actual length of plaintext is calculated during decryption.

 Another option for block ciphers is Cipher Block Chaining, known as CBC mode. When using CBC mode, an Initialization Vector (IV) is provided along with the key when starting an encrypt or decrypt operation. If CBC mode is selected and no IV is provided, an IV of all zeroes will be used.

 Cryptor also implements block bufferring, so that individual calls to `Cryptor.update()` do not have to provide data whose length is aligned to the block size. (If padding is disabled, encrypting with block ciphers does require that the *total* length of data input to `Cryptor.update()` call(s) be aligned to the block size.)

 A given `Cryptor` can only be used by one thread at a time; multiple threads can use safely different `Cryptor`s at the same time.

 As a convenience, Cryptor provides a class method, `Cryptor.crypt()` to support one shot encryption / decryption. This is useful for small data size where you can easily have the fully data to encrypt/decrypt in memory. A simple example might be:

 ```
 do {
     // The initial, plain-text data.
     let data = <Data to encrypt>

     // A buffer to write the encrypted data into.
     var encrypted = Data(repeating:0, count: 128)
     // A salt to scramble the password.
     let salt = try Cryptor.randomSalt()
     // A random IV, since we're using CBC mode.
     let initializationVector = try Cryptor.randomInitializationVector()
     // Call to encrypt the data.
     let bytesCrypted = try Cryptor.crypt(algorithm: .aes,
                                            options: [.pkcs7Padding],
                                            key: Cryptor.preparePassword("password;-)", for: .aes, salt: salt),
                                            initializationVector: initializationVector,
                                            dataIn: data,
                                            dataOut: &encrypted)

     // A buffer for the decrypted data.
     var decrypted = Data(repeating: 0, count: 128)
     // Call to decrypt the data. Note we have to pass the same password, salt, and initialization vector.
     let bytesDecrypted = try Cryptor.crypt(operation: .decrypt,
                                              algorithm: .aes,
                                              options: [.pkcs7Padding],
                                              key: Cryptor.preparePassword("password;-)", for: .aes, salt: salt),
                                              initializationVector: initializationVector,
                                              dataIn: encrypted[0 ..< bytesCrypted],
                                              dataOut: &decrypted)
 } catch let error {
     print("Error: \(error)")
 }
 ```
 */
open class Cryptor {

    // MARK: - Constants

    public enum Error : Swift.Error {
        /// Illegal parameter value.
        case paramError
        /// Insufficent buffer provided for specified operation.
        case bufferTooSmallError
        /// Insufficent buffer provided for specified operation. Used when the required buffer space can be passed back to the caller.
        case bufferTooSmallNeededError(Int)
        /// Memory allocation failure.
        case memoryFailureError
        /// Input size was not aligned properly.
        case alignmentError
        /// Input data did not decode or decrypt properly.
        case decodeError
        /// Function not implemented for the current algorithm.
        case unimplementedError
        case overflowError
        case rngFailureError
        case unspecifiedError
        case callSequenceError
        case keySizeError
        /// Key is not valid.
        case invalidKeyError
        case unknownError(Int)
        case failedToEncodePassword
        case saltSizeError
        case securityCallFailed(Int)

        public static func from(_ status: CCCryptorStatus) -> Error {
            switch Int(status) {
            case kCCParamError: return paramError
            case kCCBufferTooSmall: return bufferTooSmallError
            case kCCMemoryFailure: return memoryFailureError
            case kCCAlignmentError: return alignmentError
            case kCCDecodeError: return decodeError
            case kCCUnimplemented: return unimplementedError
            case kCCOverflow: return overflowError
            case kCCRNGFailure: return rngFailureError
            case kCCUnspecifiedError: return unspecifiedError
            case kCCCallSequenceError: return callSequenceError
            case kCCKeySizeError: return keySizeError
            case kCCInvalidKey: return invalidKeyError
            default: return unknownError(Int(status))
            }
        }
    }

    /// Operations that an Cryptor can perform.
    public enum Operation {
        /// Symmetric encryption.
        case encrypt
        /// Symmetric decryption.
        case decrypt

        public var  rawValue : CCOperation {
            switch self {
            case .encrypt: return CCOperation(kCCEncrypt)
            case .decrypt: return CCOperation(kCCDecrypt)
            }
        }
    }

    /// Encryption algorithms implemented by this module.
    public enum Algorithm {
        /// Advanced Encryption Standard, 128-bit block
        case aes
        /// Data Encryption Standard. Only use for interoperating with older data. Do not use this for newer systems. It's no longer considered secure. Use AES instead.
        case des
        /// Triple-DES, three key, EDE configuration. This is no longer preferred for newer systems. Use AES instead.
        case threeDES
        /// CAST
        case cast
        /// RC4 stream cipher
        case rc4
        /// RC2 stream cipher
        case rc2
        /// Blowfish block cipher
        case blowfish

        public var rawValue : CCAlgorithm {
            switch self {
            case .aes:      return CCAlgorithm(kCCAlgorithmAES)
            case .des:      return CCAlgorithm(kCCAlgorithmDES)
            case .threeDES: return CCAlgorithm(kCCAlgorithm3DES)
            case .cast:     return CCAlgorithm(kCCAlgorithmCAST)
            case .rc4:      return CCAlgorithm(kCCAlgorithmRC4)
            case .rc2:      return CCAlgorithm(kCCAlgorithmRC2)
            case .blowfish: return CCAlgorithm(kCCAlgorithmBlowfish)
            }
        }
    }

    public struct Options : OptionSet {
        public let rawValue : UInt32

        public init(rawValue: UInt32) {
            self.rawValue = rawValue
        }

        /// Perform PKCS7 padding.
        public static let pkcs7Padding = Options(rawValue: UInt32(kCCOptionPKCS7Padding))
        /// Electronic Code Book Mode. Default is CBC.
        public static let ecbMode      = Options(rawValue: UInt32(kCCOptionECBMode))
    }

    public enum Mode : UInt32 {
        /// Electronic Code Book Mode.
        case ecb = 1
        /// Cipher Block Chaining Mode.
        case cbc = 2
        /// Cipher Feedback Mode.
        case cfb = 3
        /// ???
        case ctr = 4
        /// Output Feedback Mode.
        case ofb = 7
        /// RC4 as a streaming cipher is handled internally as a mode.
        case rc4 = 9
        ///Cipher Feedback Mode producing 8 bits per round.
        case cfb8 = 10
    }

    /// Padding for Block Ciphers
    public enum Padding : UInt32 {
        /// No padding
        case none = 0
        /// PKCS7 padding.
        case pkcs7 = 1
    }

    /**
     Mode options - Not currently in use.

     Values used to specify options for modes. This was used for counter  mode operations in 10.8, now only Big Endian mode is supported.
     */
    public struct ModeOptions : OptionSet {
        public let rawValue : UInt32

        public init(rawValue: UInt32) {
            self.rawValue = rawValue
        }

        /// CTR Mode Big Endian.
        static let ctrBigEndian = kCCModeOptionCTR_BE
    }

    /**
     Key sizes

     Key sizes, in bytes, for supported algorithms.  Use these constants to select any keysize variants you wish to use  for algorithms that support them (ie AES-128, AES-192, AES-256).
     */
    public struct KeySize : RawRepresentable {
        public var rawValue: Int

        public init(rawValue: Int) {
            self.rawValue = rawValue
        }
        public init(_ rawValue: Int) {
            self.rawValue = rawValue
        }

        public typealias RawValue = Int

        static let aes128 = KeySize(kCCKeySizeAES128)
        static let aes192 = KeySize(kCCKeySizeAES192)
        static let aes256 = KeySize(kCCKeySizeAES256)
        static let des = KeySize(kCCKeySizeDES)
        static let threeDES = KeySize(kCCKeySizeDES)
        static let minCAST = KeySize(kCCKeySizeMinCAST)
        static let maxCAST = KeySize(kCCKeySizeMaxCAST)
        static let minRC4 = KeySize(kCCKeySizeMinRC4)
        static let maxRC4 = KeySize(kCCKeySizeMaxRC4)
        static let minRC2 = KeySize(kCCKeySizeMinRC2)
        static let maxRC2 = KeySize(kCCKeySizeMaxRC2)
        static let minBlowfish = KeySize(kCCKeySizeMinBlowfish)
        static let maxBlowfish = KeySize(kCCKeySizeMaxBlowfish)

        static func < (lhs: Int, rhs: KeySize) -> Bool { return lhs < rhs.rawValue }
        static func <= (lhs: Int, rhs: KeySize) -> Bool { return lhs <= rhs.rawValue }
        static func > (lhs: Int, rhs: KeySize) -> Bool { return lhs > rhs.rawValue }
        static func >= (lhs: Int, rhs: KeySize) -> Bool { return lhs >= rhs.rawValue }
        static func == (lhs: Int, rhs: KeySize) -> Bool { return lhs == rhs.rawValue }
        static func != (lhs: Int, rhs: KeySize) -> Bool { return lhs != rhs.rawValue }
        static func < (lhs: KeySize, rhs: Int) -> Bool { return lhs.rawValue < rhs }
        static func <= (lhs: KeySize, rhs: Int) -> Bool { return lhs.rawValue <= rhs }
        static func > (lhs: KeySize, rhs: Int) -> Bool { return lhs.rawValue > rhs }
        static func >= (lhs: KeySize, rhs: Int) -> Bool { return lhs.rawValue >= rhs }
        static func == (lhs: KeySize, rhs: Int) -> Bool { return lhs.rawValue == rhs }
        static func != (lhs: KeySize, rhs: Int) -> Bool { return lhs.rawValue != rhs }

        public static func `for`(_ algorithm: Algorithm) -> (min: KeySize, max: KeySize) {
            switch algorithm {
            case .aes:      return (min: .aes128, max: .aes128)
            case .des:      return (min: .des, max: .des)
            case .threeDES: return (min: .threeDES, max: .threeDES)
            case .cast:     return (min: .minCAST, max: .maxCAST)
            case .rc4:      return (min: .minRC4, max: .maxRC4)
            case .rc2:      return (min: .minRC2, max: .maxRC2)
            case .blowfish: return (min: .minBlowfish, max: .maxBlowfish)
            }
        }
    }

    /**
     Block sizes

     Block sizes, in bytes, for supported algorithms.
     */
    public struct BlockSize : RawRepresentable {
        public var rawValue : Int

        public init(rawValue: Int) {
            self.rawValue = rawValue
        }

        public init(_ rawValue: Int) {
            self.rawValue = rawValue
        }

        /// AES block size (currently, only 128-bit blocks are supported).
        static public let aes128 = BlockSize(kCCBlockSizeAES128)
        /// DES block size.
        static public let des = BlockSize(kCCBlockSizeDES)
        /// Triple DES block size.
        static public let threeDES = BlockSize(kCCBlockSize3DES)
        /// CAST block size.
        static public let cast = BlockSize(kCCBlockSizeCAST)
        /// Blowfish block size.
        static public let blowfish = BlockSize(kCCBlockSizeBlowfish)
        /// RC2 block size.
        static public let rc2 = BlockSize(kCCBlockSizeRC2)

        public static func `for`(_ algorithm: Algorithm) -> BlockSize {
            switch algorithm {
            case .aes:      return .aes128
            case .des:      return .des
            case .threeDES: return .threeDES
            case .cast:     return .cast
            case .rc4:      return .rc2
            case .rc2:      return .rc2
            case .blowfish: return .blowfish
            }
        }

        // Because we often want to use these with math...
        public static func + <T: BinaryInteger> (lhs: T, rhs: BlockSize) -> T { return lhs + T(rhs.rawValue) }
        public static func + <T: BinaryInteger> (lhs: BlockSize, rhs: T) -> T { return T(lhs.rawValue) + rhs }
        public static func - <T: BinaryInteger> (lhs: T, rhs: BlockSize) -> T { return lhs - T(rhs.rawValue) }
        public static func - <T: BinaryInteger> (lhs: BlockSize, rhs: T) -> T { return T(lhs.rawValue) - rhs }
        public static func * <T: BinaryInteger> (lhs: T, rhs: BlockSize) -> T { return lhs * T(rhs.rawValue) }
        public static func * <T: BinaryInteger> (lhs: BlockSize, rhs: T) -> T { return T(lhs.rawValue) * rhs }
        public static func / <T: BinaryInteger> (lhs: T, rhs: BlockSize) -> T { return lhs / T(rhs.rawValue) }
        public static func / <T: BinaryInteger> (lhs: BlockSize, rhs: T) -> T { return T(lhs.rawValue) / rhs }
        public static func % <T: BinaryInteger> (lhs: T, rhs: BlockSize) -> T { return lhs % T(rhs.rawValue) }
        public static func % <T: BinaryInteger> (lhs: BlockSize, rhs: T) -> T { return T(lhs.rawValue) % rhs }
    }

    // MARK: - Properties

    internal var cryptor = UnsafeMutablePointer<CCCryptorRef?>.allocate(capacity: 1)

    // MARK: - Creation

    /**
     Create a cryptographic context.

     - parameter operation: Defines the basic operation: `Operation.encrypt` or `Operation.decrypt`.
     - parameter algorithm: Defines the algorithm.
     - parameter options: A word of flags defining options. See discussion for the CCOptions type.
     - parameter key: Raw key material, length keyLength bytes. Length of key must be appropriate for the selected operation and algorithm. Some algorithms  provide for varying key lengths.
     - parameter initializationVector: Initialization vector, optional. Used by block ciphers when Cipher Block Chaining (CBC) mode is enabled. If present, must be the same length as the selected algorithm's block size. If CBC mode is selected (by the absence of the `kCCOptionECBMode` bit in the options flags) and no IV is present, a nil (all zeroes) IV will be used. This parameter is ignored if ECB mode is used or if a stream cipher algorithm is selected. For sound encryption, always initialize `initializationVector` with random data. You may call `randomInitializationVector` to generate one, just make sure to write this value (it may be public) along with your encrypted data, as it will be required to decrypt.

     - throws: A `Cryptor.Error` if something goes wrong.

     */
    public init(operation: Operation,
                algorithm: Algorithm,
                options: Options,
                key: Data,
                initializationVector: IV?) throws {
        let status = Cryptor.dataWithUnsafeBytes(key) { (keyBytes, keyLength) -> CCCryptorStatus in
            return Cryptor.dataWithUnsafeBytes(initializationVector) { (ivBytes, _) -> CCCryptorStatus in
                return CCCryptorCreate(operation.rawValue,
                                       algorithm.rawValue,
                                       options.rawValue,
                                       keyBytes, keyLength,
                                       ivBytes,
                                       cryptor)
            }
        }
        if status != kCCSuccess {
            throw Error.from(status)
        }
    }

    /**
     Create a cryptographic context using caller-supplied memory.

     - parameter operation: Defines the basic operation: `Operation.encrypt` or `Operation.decrypt`.
     - parameter algorithm: Defines the algorithm.
     - parameter options: A word of flags defining options. See discussion
     for the CCOptions type.
     - parameter key: Raw key material, length keyLength bytes. Length of key material. Must be appropriate for the selected operation and algorithm. Some algorithms  provide for varying key lengths.
     - parameter initializationVector: Initialization vector, optional. Used by block ciphers when Cipher Block Chaining (CBC) mode is enabled. If present, must be the same length as the selected algorithm's block size. If CBC mode is selected (by the absence of the `Options.ecbMode` bit in the options flags) and no IV is present, a NULL (all zeroes) IV will be used. This parameter is ignored if ECB mode is used or if a stream cipher algorithm is selected. For sound encryption, always initialize iv with random data. You may call `randomInitializationVector` to generate one, just make sure to write this value (it may be public) along with your encrypted data, as it will be required to decrypt.
     - parameter data A pointer to caller-supplied memory from which the `Cryptor` will be created. You can call BlockSize.for() to get the currently required size. This is more reliable than hard coding the block size.
     - parameter dataUsed: Optional. If present, the actual number of bytes of the caller-supplied memory which was consumed by creation of the `Cryptor` is returned here. Also, if the supplied memory is of insufficent size to create a `Cryptor`, `CryptorError.bufferTooSmallNeededError(Int)` is thrown with the minimum required buffer size.

     - throws: Possible error returns are CryptorError.paramError and CryptorError.bufferTooSmall.

     The `Cryptor` created by this function must be disposed of via `release()` which clears sensitive data and deallocates memory when the caller is finished using the `Cryptor`. Note that `release()` doesn't release the actual `Cryptor`, just the underlying memory used.
    */
    public init(operation: Operation,
                algorithm: Algorithm,
                options: Options,
                key: Data,
                initializationVector: IV?,
                data: Data,
                dataUsed: inout Int?) throws {
        let status = Cryptor.dataWithUnsafeBytes(key) { (keyBytes, keyLength) -> CCCryptorStatus in
            return Cryptor.dataWithUnsafeBytes(initializationVector) { (ivBytes, _) -> CCCryptorStatus in
                return Cryptor.dataWithUnsafeBytes(data) { (dataBytes, dataLength) -> CCCryptorStatus in
                    var dataUsedIntermediate = 0
                    let result = CCCryptorCreateFromData(operation.rawValue,
                                                         algorithm.rawValue,
                                                         options.rawValue,
                                                         keyBytes, keyLength,
                                                         ivBytes,
                                                         dataBytes, dataLength,
                                                         cryptor,
                                                         &dataUsedIntermediate)
                    dataUsed = dataUsedIntermediate
                    return result
                }
            }
        }
        if status != kCCSuccess {
            if status == kCCBufferTooSmall && dataUsed != nil {
                throw Error.bufferTooSmallNeededError(dataUsed!)
            }
            throw Error.from(status)
        }
    }

    /**
     Create a cryptographic context.

     - parameter operation: Defines the basic operation: `Operation.encrypt` or `Operation.decrypt`.
     - parameter mode: Specifies the cipher mode to use for operations.
     - parameter algorithm: Defines the algorithm.
     - parameter padding: Specifies the padding to use.
     - parameter initializationVector: Initialization vector, optional. Used by block ciphers with the following modes

        * Cipher Block Chaining (CBC)
        * Cipher Feedback (CFB and CFB8)
        * Output Feedback (OFB)
        * Counter (CTR)

        If present, must be the same length as the selected algorithm's block size.  If no IV is present, a NULL (all zeroes) IV will be used. For sound encryption,  always initialize `initializationVector` with random data. You can call `randomInitializationVector()` to generate a cryptographically secure IV.

        This parameter is ignored if ECB mode is used or if a stream cipher algorithm is selected.

     - parameter key: Raw key material.
     - parameter tweak: Raw key material. Used for the tweak key in XEX-based Tweaked CodeBook (XTS) mode. Some algorithms  provide for varying key lengths.  For XTS this is the same length as the encryption key.
     - parameter numRounds: The number of rounds of the cipher to use.  0 uses the default.
     - parameter options: See discussion for the `ModeOptions` type.

     - throws: Possible error returns are `CyptorError.paramError` and `CryptorError.memoryFailure`.
 */
    public init(operation: Operation,
                mode: Mode,
                algorithm: Algorithm,
                padding: Padding,
                initializationVector: IV?,
                key: Data,
                tweak: Data?,
                numRounds: Int32,
                options: ModeOptions) throws {
        let status: CCCryptorStatus = Cryptor.dataWithUnsafeBytes(key) { (keyBytes, keyLength) -> CCCryptorStatus in
            return Cryptor.dataWithUnsafeBytes(initializationVector) { (ivBytes, _) -> CCCryptorStatus in
                return Cryptor.dataWithUnsafeBytes(tweak) { (tweakBytes, tweakLength) -> CCCryptorStatus in
                    return CCCryptorCreateWithMode(operation.rawValue,
                                                   mode.rawValue,
                                                   algorithm.rawValue,
                                                   padding.rawValue,
                                                   ivBytes,
                                                   keyBytes, keyLength,
                                                   tweakBytes, tweakLength,
                                                   numRounds,
                                                   options.rawValue,
                                                   cryptor)
                }
            }
        }
        if status != kCCSuccess {
            throw Error.from(status)
        }
    }

    deinit {
        // TODO: Provide a function to do this explicitly, since this releases and clears the memory used during cypto operations.
        if cryptor.pointee != nil {
            CCCryptorRelease(cryptor.pointee)
        }
    }

    // MARK: - Private Utilties

    /**
     Wires down a Data's memory so it can be safely passed to one of the underlying library functions.

     - parameter data: The data to access.
     - parameter block: The block to call.
     - parameter pointer: The pointer to the `Data`'s underlying data.
     - parameter length: The length of `Data`. This is passed to avoid capturing the `Data` object itself.

     - returns: The specified type `T`. This is useful for passing out the return value of a system call.
     */
    static internal func dataWithUnsafeBytes<T>(_ data: Data?, block: (_ pointer: UnsafeRawPointer?, _ length: Int) -> T) -> T {
        if let data = data {
            return data.withUnsafeBytes { (bytes) -> T in
                block(bytes.baseAddress, data.count)
            }
        } else {
            return block(nil, 0)
        }
    }

    /**
     Wires down a Data's memory so it can be safely passed to one of the underlying library functions.

     - parameter data: The data to access. Data must be mutable.
     - parameter block: The block to call.
     - parameter pointer: The pointer to the `Data`'s underlying data.
     - parameter length: The length of `Data`. This is passed to avoid capturing the `Data` object itself.

     - returns: The specified type `T`. This is useful for passing out the return value of a system call.
          */
    static internal func dataWithUnsafeMutableBytes<T>(_ data: inout Data, block: (_ pointer: UnsafeMutableRawPointer?, _ length: Int) -> T) -> T {
        let length = data.count
        return data.withUnsafeMutableBytes { (bytes) -> T in
            block(bytes.baseAddress, length)
        }
    }

    // MARK: Methods

    /**
     Free the underlying memory used for cryptographic functions. It can be a good idea to call this function when you're done working with your `Cryptor`, as it will free / zero out any memory used, rather than waiting for the receiver to be garbage collected.

     No cryptographic calls to the receiver are valid after this call.
    */
    open func release() throws -> Void {
        let result = CCCryptorRelease(cryptor.pointee)
        cryptor.pointee = nil
        if result != kCCSuccess {
            throw Error.from(result)
        }
    }

    /**
     Process (encrypt, decrypt) some data. The result, if any, is written to a caller-provided buffer.

     - parameter dataIn: Data to process, length dataInLength bytes.

     - parameter dataOut: Result is written here. Allocated by caller.  Encryption and decryption can be performed "in-place", with the same buffer used for input and output. The in-place operation is not suported for ciphers modes that work with blocks of data such as CBC and ECB.

     - returns: The number of bytes written to `dataOut`.

     - throws: `CryptorError.bufferTooSmall` indicates insufficent space in the dataOut buffer. The caller can use `getOutputLength()` to determine the required output buffer size in this case. The operation can be retried; no state is lost when this is returned.

     This routine can be called multiple times. The caller does not need to align input data lengths to block sizes; input is bufferred as necessary for block ciphers.

     When performing symmetric encryption with block ciphers, and padding is enabled via `Option.pkcs7Padding`, the total number of bytes provided by all the calls to this function when encrypting can be arbitrary (i.e., the total number of bytes does not have to be block aligned). However if padding is disabled, or when decrypting, the total number of bytes does have to be aligned to the block size; otherwise `final()` will throw `CryptorError.alignmentError`.

     A general rule for the size of the output buffer which must be provided by the caller is that for block ciphers, the output length is never larger than the input length plus the block size. For stream ciphers, the output length is always exactly the same as the input length. See the discussion for `getOutputLength()` for more information on this topic.

     Generally, when all data has been processed, call `final()`.

     In the following cases, the `final()` is superfluous as it will not yield any data nor throw an error:

     1. Encrypting or decrypting with a block cipher with padding disabled, when the total amount of data provided to update() is an integral multiple of the block size.

     2. Encrypting or decrypting with a stream cipher.
     */
    open func update(dataIn: Data, dataOut: inout Data) throws -> Int {
        var bytesWritten = 0
        let status = Cryptor.dataWithUnsafeBytes(dataIn) { (dataBytes, dataLength) -> CCCryptorStatus in
            return Cryptor.dataWithUnsafeMutableBytes(&dataOut) { (dataOutBytes, dataOutLength) -> CCCryptorStatus in
                return CCCryptorUpdate(cryptor.pointee,
                                       dataBytes, dataLength,
                                       dataOutBytes, dataOutLength,
                                       &bytesWritten)
            }
        }
        if status != kCCSuccess {
            throw Error.from(status)
        }
        return bytesWritten
    }

    /**
     Finish an encrypt or decrypt operation, and obtain the (possible) final data output.

     - parameter dataOut: Result is written here. Allocated by caller.

     - returns: The number of bytes written to dataOut.

     - throws:
        * `CryptorError.bufferTooSmallError` indicates insufficent space in the dataOut buffer. The caller can use `getOutputLength()` to determine the required output buffer size in this case. The operation can be retried; no state is lost when this is returned.
        * `CryptorError.alignmentError` When decrypting, or when encrypting with a block cipher with padding disabled, kCCAlignmentError will be returned if the total number of bytes provided to CCCryptUpdate() is not an integral multiple of the current algorithm's block size.
        * `CryptorError.decodeError`  Indicates garbled ciphertext or the wrong key during decryption. This can only be returned while decrypting with padding enabled.

     Except when `CryptorError.bufferTooSmallError` is returned, the Cryptor can no longer be used for subsequent operations unless `reset()` is called on it.

     It is not necessary to call `final()` when performing symmetric encryption or decryption if padding is disabled, or when using a stream cipher.

     It is not necessary to call `final()` prior to `release()` when aborting an operation.
     */
    open func final(dataOut: inout Data) throws -> Int {
        var bytesWritten : Int = 0
        let status = Cryptor.dataWithUnsafeMutableBytes(&dataOut) { (dataOutBytes, dataOutLength) -> CCCryptorStatus in
            return CCCryptorFinal(cryptor.pointee,
                                  dataOutBytes, dataOutLength,
                                  &bytesWritten)
        }
        if status != kCCSuccess {
            throw Error.from(status)
        }
        return bytesWritten
    }

    /**
     Determine output buffer size required to process a given input size.

     - parameter inputLength: The length of data which will be provided to` update()`.
     - parameter final: If `false`, the returned value will indicate the output buffer space needed when `inputLength` bytes are provided to `update()`. When `final` is `true`, the returned value will indicate the total combined buffer space needed when `inputLength` bytes are provided to `update()` and then `final()` is called.

     - returns: The maximum buffer space need to perform `update()` and optionally `final()`.

     Some general rules apply that allow clients of this module to know a priori how much output buffer space will be required in a given situation. For stream ciphers, the output size is always equal to the input size, and `final()` never produces any data. For block ciphers, the output size will always be less than or equal to the input size plus the size of one block. For block ciphers, if the input size provided to each call to `update()` is is an integral multiple of the block size, then the output size for each call to `update()` is less than or equal to the input size for that call to `update()`. `final()` only produces output when using a block cipher with padding enabled.
    */
    open func getOutputLength(for inputLength: Int, final: Bool) -> Int {
        return CCCryptorGetOutputLength(cryptor.pointee, inputLength, final)
    }

    /**
     Reinitializes the receiver with a (possibly) new initialization vector. The receiver's key is unchanged. Use only for CBC mode.

     - parameter initializationVector: Optional initialization vector; if present, must be the same size as the current algorithm's block size. For sound encryption, always initialize `initializationVector` with random data.

     - throws: The only possible errors are `CryptorError.paramError` and `CryptorError.unimplemented`. On macOS 10.13, iOS 11, watchOS 4 and tvOS 11 returns `CryptorError.unimplemented` for modes other than CBC.

     This can be called when the receiver has data pending (*i.e.* in a padded mode operation before `final()` is called); however any pending data will be lost in that case.
     */
    open func reset(initializationVector: Data?) throws -> Void {
        let status = Cryptor.dataWithUnsafeBytes(initializationVector) { (ivBytes, _) -> CCCryptorStatus in
            return CCCryptorReset(cryptor.pointee, ivBytes)
        }
        if status != kCCSuccess {
            throw Error.from(status)
        }
    }

    /**
     Stateless, one-shot encrypt or decrypt operation. This basically performs a sequence of `init()`, `update()`, `final()`, and `release()`. It's a good option for encrypting / decrypting small blocks of data.

     - parameter algorithm: Defines the encryption algorithm.
     - parameter operation: Defines the basic operation: `Operation.encrypt` or `Operation.decrypt`.
     - parameter options: A word of flags defining options. See discussion for the `Options` type.
     - parameter key: Raw key material, length keyLength bytes.

     - parameter initializationVector: Initialization vector, optional. Used for Cipher Block Chaining (CBC) mode. If present, must be the same length as the selected algorithm's block size. If CBC mode is selected (by the absence of any mode bits in the options flags) and no IV is present, a nil (all zeroes) IV will be used. This is ignored if ECB mode is used or if a stream cipher algorithm is selected. For sound encryption, always initialize IV with random data.

     - parameter dataIn: Data to encrypt or decrypt, length dataInLength bytes.

     - parameter dataOut: Result is written here. Allocated by caller. Encryption and decryption can be performed "in-place", with the same buffer used for input and output.

     - returns: The number of bytes written to dataOut.

     - throws:
        * `CryptorError.bufferTooSmallError` indicates insufficent space in the dataOut buffer. In this case, the *dataOutMoved parameter will indicate the size of the buffer needed to complete the operation. The operation can be retried with minimal runtime penalty.
        * `CryptorError.alignmentError` indicates that dataInLength was not properly aligned. This can only be returned for block ciphers, and then only when decrypting or when encrypting with block with padding disabled.
        * `CryptorError.decodeError`  Indicates improperly formatted ciphertext or a "wrong key" error; occurs only during decrypt operations.
     */
    @discardableResult
    open class func crypt(operation: Operation,
                          algorithm: Algorithm,
                          options: Options,
                          key: Data,
                          initializationVector: Data? = nil,
                          dataIn: Data,
                          dataOut: inout Data) throws -> Int {
        var bytesWritten : Int = 0
        let status = Cryptor.dataWithUnsafeBytes(dataIn) { (dataInBytes, dataInLength) -> CCCryptorStatus in
            return Cryptor.dataWithUnsafeBytes(key) { (keyBytes, keyLength) -> CCCryptorStatus in
                return Cryptor.dataWithUnsafeBytes(initializationVector) { (ivBytes, _) -> CCCryptorStatus in
                    return Cryptor.dataWithUnsafeMutableBytes(&dataOut) { (dataOutBytes, dataOutLength) -> CCCryptorStatus in
                        return CCCrypt(operation.rawValue,
                                       algorithm.rawValue,
                                       options.rawValue,
                                       keyBytes, keyLength,
                                       ivBytes,
                                       dataInBytes, dataInLength,
                                       dataOutBytes, dataOutLength,
                                       &bytesWritten)
                    }
                }
            }
        }
        if status != kCCSuccess {
            if status == kCCBufferTooSmall {
                throw Error.bufferTooSmallNeededError(bytesWritten)
            }
            throw Error.from(status)
        }
        return bytesWritten
    }

    // MARK: - Useful Utilities

    /**
     Defines some common sizes.
     */
    public struct Size : RawRepresentable {
        public var rawValue : Int
        public init(rawValue: Int) {
            self.rawValue = rawValue
        }
        public init(_ rawValue: Int) {
            self.rawValue = rawValue
        }
        /// Size of a salt.
        public static let salt = Size(8)
        /// Size of an IV.
        public static let aesInitializationVector = Size(kCCBlockSizeAES128)
    }

    /**
     Generates a cryptographically secure random data useful in salting a password. The return data will have length `Size.salt`.

     - returns: The random salt.
     - throws: `CryptorError.unknownError` if the data cannot be generated for some reason. This should be exceedingly rare.
     */
    open class func randomSalt() throws -> Data {
        // If this fails, something had already gone horrible wrong, so just crash.
        return try Data(randomDataOfLength: Size.salt.rawValue)
    }

    /**
     Returns a randomly generated initialization vector by calling `randomData(length:)` with a length of 

     - returns: The random IV.
     - throws: `CryptorError.unknownError` if the data cannot be generated for some reason. This should be exceedingly rare.
     */
    open class func randomInitializationVector(length: Size = .aesInitializationVector) throws -> Data {
        // If this fails, something had already gone horrible wrong, so just crash.
        return try Data(randomDataOfLength: length.rawValue)
    }

    open class func randomKey(for algorithm: Algorithm) throws -> Data {
        // If this fails, something had already gone horrible wrong, so just crash.
        return try Data(randomDataOfLength: KeySize.for(algorithm).min.rawValue)
    }

}

public typealias IV = Data

public extension IV {

    /// The default initialization vector. This is basically 16 zeros, and isn't an ideal choice.
    static let `default` = Data(repeating: 0, count: Cryptor.Size.aesInitializationVector.rawValue)

}

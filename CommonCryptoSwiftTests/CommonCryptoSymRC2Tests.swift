//
//  CommonCryptoSymRC2Tests.swift
//  CommonCryptoSwiftTests
//
//  Created by AJ Raftis on 3/6/21.
//

import XCTest
import CommonCryptoSwift

class CommonCryptoSymRC2Tests: XCTestCase {

    func testRC2() throws {
        var keyStr : String
        var iv : String?
        var plainText : String
        var cipherText : String
        var alg : Cryptor.Algorithm
        var options : Cryptor.Options
        var retval : Bool
        var rkeylen : Int
        var ekeylenBits : Int

        alg = .rc2
        iv = nil
        options = []

        rkeylen = 8
        ekeylenBits = 63
        keyStr =    "0000000000000000"
        plainText = "0000000000000000"
        cipherText = "ebb773f993278eff"
        retval = try cryptTest(keyStr: keyStr, ivStr: iv, alg: alg, options: options, cipherText: cipherText, plainText: plainText, log: true)
        XCTAssert(retval, "RC2 \(rkeylen) byte Key (effective \(ekeylenBits) bits) One-Shot")
        retval = multiCryptTest(keyStr: keyStr, ivStr: iv, alg: alg, options: options, cipherText: cipherText, plainText: plainText)
        XCTAssert(retval, "RC2 \(rkeylen) byte Key (effective \(ekeylenBits) bits) Multi")

        rkeylen = 8
        ekeylenBits = 64
        keyStr =    "ffffffffffffffff"
        plainText = "ffffffffffffffff"
        cipherText = "278b27e42e2f0d49"
        retval = try cryptTest(keyStr: keyStr, ivStr: iv, alg: alg, options: options, cipherText: cipherText, plainText: plainText, log: true)
        XCTAssert(retval, "RC2 \(rkeylen) byte Key (effective \(ekeylenBits) bits) One-Shot")
        retval = multiCryptTest(keyStr: keyStr, ivStr: iv, alg: alg, options: options, cipherText: cipherText, plainText: plainText)
        XCTAssert(retval, "RC2 \(rkeylen) byte Key (effective \(ekeylenBits) bits) Multi")

        rkeylen = 8
        ekeylenBits = 64
        keyStr =    "3000000000000000"
        plainText = "1000000000000001"
        cipherText = "30649edf9be7d2c2"
        retval = try cryptTest(keyStr: keyStr, ivStr: iv, alg: alg, options: options, cipherText: cipherText, plainText: plainText, log: true)
        XCTAssert(retval, "RC2 \(rkeylen) byte Key (effective \(ekeylenBits) bits) One-Shot")
        retval = multiCryptTest(keyStr: keyStr, ivStr: iv, alg: alg, options: options, cipherText: cipherText, plainText: plainText)
        XCTAssert(retval, "RC2 \(rkeylen) byte Key (effective \(ekeylenBits) bits) Multi")

        if false { // WEIRDCASE
            rkeylen = 1
            ekeylenBits = 64
            keyStr =    "88"
            plainText = "0000000000000000"
            cipherText = "61a8a244adacccf0"
            retval = try cryptTest(keyStr: keyStr, ivStr: iv, alg: alg, options: options, cipherText: cipherText, plainText: plainText)
            XCTAssert(retval, "RC2 \(rkeylen) byte Key (effective \(ekeylenBits) bits) One-Shot")
            retval = multiCryptTest(keyStr: keyStr, ivStr: iv, alg: alg, options: options, cipherText: cipherText, plainText: plainText)
            XCTAssert(retval, "RC2 \(rkeylen) byte Key (effective \(ekeylenBits) bits) Multi")

            rkeylen = 7
            ekeylenBits = 64
            keyStr = "88bca90e90875a"
            plainText = "0000000000000000"
            cipherText = "6ccf4308974c267f"
            retval = try cryptTest(keyStr: keyStr, ivStr: iv, alg: alg, options: options, cipherText: cipherText, plainText: plainText)
            XCTAssert(retval, "RC2 \(rkeylen) byte Key (effective \(ekeylenBits) bits) One-Shot")
            retval = multiCryptTest(keyStr: keyStr, ivStr: iv, alg: alg, options: options, cipherText: cipherText, plainText: plainText)
            XCTAssert(retval, "RC2 \(rkeylen) byte Key (effective \(ekeylenBits) bits) Multi")

            rkeylen = 16
            ekeylenBits = 64
            keyStr = "88bca90e90875a7f0f79c384627bafb2"
            plainText = "0000000000000000"
            cipherText = "1a807d272bbe5db1"
            retval = try cryptTest(keyStr: keyStr, ivStr: iv, alg: alg, options: options, cipherText: cipherText, plainText: plainText)
            XCTAssert(retval, "RC2 \(rkeylen) byte Key (effective \(ekeylenBits) bits) One-Shot")
            retval = multiCryptTest(keyStr: keyStr, ivStr: iv, alg: alg, options: options, cipherText: cipherText, plainText: plainText)
            XCTAssert(retval, "RC2 \(rkeylen) byte Key (effective \(ekeylenBits) bits) Multi")
        }

        rkeylen = 16
        ekeylenBits = 128
        keyStr = "88bca90e90875a7f0f79c384627bafb2"
        plainText = "0000000000000000"
        cipherText = "2269552ab0f85ca6"
        retval = try cryptTest(keyStr: keyStr, ivStr: iv, alg: alg, options: options, cipherText: cipherText, plainText: plainText, log: true)
        XCTAssert(retval, "RC2 \(rkeylen) byte Key (effective \(ekeylenBits) bits) One-Shot")
        retval = multiCryptTest(keyStr: keyStr, ivStr: iv, alg: alg, options: options, cipherText: cipherText, plainText: plainText)
        XCTAssert(retval, "RC2 \(rkeylen) byte Key (effective \(ekeylenBits) bits) Multi")
    }

}

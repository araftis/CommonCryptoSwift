//
//  CommonCryptoSymCBCTests.swift
//  CommonCryptoSwiftTests
//
//  Created by AJ Raftis on 3/6/21.
//

import XCTest
import CommonCryptoSwift

class CommonCryptoSymCBCTests: XCTestCase {

    func testCBC() throws {
        var keyStr = "000102030405060708090a0b0c0d0e0f"
        var iv : String? = "0f0e0d0c0b0a09080706050403020100"
        var alg = Cryptor.Algorithm.aes
        var options : Cryptor.Options = [.pkcs7Padding]
        var retval : Bool
        var plainText : String
        var cipherText : String

        // 1
        plainText  = "0a"
        cipherText = "a385b047a4108a8748bf96b435738213"
        retval = try cryptTest(keyStr: keyStr, ivStr: iv, alg: alg, options: options, cipherText: cipherText, plainText: plainText, log: true)
        XCTAssert(retval, "CBC with Padding 1 byte CCCrypt")
        retval = multiCryptTest(keyStr: keyStr, ivStr: iv, alg: alg, options: options, cipherText: cipherText, plainText: plainText)
        XCTAssert(retval, "CBC with Padding 1 byte Multiple Updates")

        // 15
        plainText  = "0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a"
        cipherText = "324a44cf3395b14214861084019f9257"
        retval = try cryptTest(keyStr: keyStr, ivStr: iv, alg: alg, options: options, cipherText: cipherText, plainText: plainText, log: true)
        XCTAssert(retval, "CBC with Padding 15 byte CCCrypt")
        retval = multiCryptTest(keyStr: keyStr, ivStr: iv, alg: alg, options: options, cipherText: cipherText, plainText: plainText)
        XCTAssert(retval, "CBC with Padding 15 byte Multiple Updates")

        // 16
        plainText  = "0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a"
        cipherText = "16d67a52c1e8384f7ed887c2011605346544febcf84574c334f1145d17567047"
        retval = try cryptTest(keyStr: keyStr, ivStr: iv, alg: alg, options: options, cipherText: cipherText, plainText: plainText, log: true)
        XCTAssert(retval, "CBC with Padding 16 byte CCCrypt")
        retval = multiCryptTest(keyStr: keyStr, ivStr: iv, alg: alg, options: options, cipherText: cipherText, plainText: plainText)
        XCTAssert(retval, "CBC with Padding 16 byte Multiple Updates")

        // 17
        plainText  = "0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a"
        cipherText = "16d67a52c1e8384f7ed887c2011605348b72cecb00bbc00f328af6bb69085b02"
        retval = try cryptTest(keyStr: keyStr, ivStr: iv, alg: alg, options: options, cipherText: cipherText, plainText: plainText, log: true)
        XCTAssert(retval, "CBC with Padding 17 byte CCCrypt")
        retval = multiCryptTest(keyStr: keyStr, ivStr: iv, alg: alg, options: options, cipherText: cipherText, plainText: plainText)
        XCTAssert(retval, "CBC with Padding 17 byte Multiple Updates")

        // 31
        plainText  = "0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a"
        cipherText = "16d67a52c1e8384f7ed887c2011605347175cf878a75bc1947ae79c6c6835030"
        retval = try cryptTest(keyStr: keyStr, ivStr: iv, alg: alg, options: options, cipherText: cipherText, plainText: plainText, log: true)
        XCTAssert(retval, "CBC with Padding 31 byte CCCrypt")
        retval = multiCryptTest(keyStr: keyStr, ivStr: iv, alg: alg, options: options, cipherText: cipherText, plainText: plainText)
        XCTAssert(retval, "CBC with Padding 31 byte Multiple Updates")

        // 32
        plainText  = "0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a"
        cipherText = "16d67a52c1e8384f7ed887c20116053486869f3b83f3b3a83531e4169e97b7244a49199daa033fa88f07dd4be52ae78e"
        retval = try cryptTest(keyStr: keyStr, ivStr: iv, alg: alg, options: options, cipherText: cipherText, plainText: plainText, log: true)
        XCTAssert(retval, "CBC with Padding 32 byte CCCrypt")
        retval = multiCryptTest(keyStr: keyStr, ivStr: iv, alg: alg, options: options, cipherText: cipherText, plainText: plainText)
        XCTAssert(retval, "CBC with Padding 32 byte Multiple Updates")

        // 33
        plainText  = "0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a"
        cipherText = "16d67a52c1e8384f7ed887c20116053486869f3b83f3b3a83531e4169e97b724d0080fb874dd556fa86b314acc4f597b"
        retval = try cryptTest(keyStr: keyStr, ivStr: iv, alg: alg, options: options, cipherText: cipherText, plainText: plainText, log: true)
        XCTAssert(retval, "CBC with Padding 33 byte CCCrypt")
        retval = multiCryptTest(keyStr: keyStr, ivStr: iv, alg: alg, options: options, cipherText: cipherText, plainText: plainText)
        XCTAssert(retval, "CBC with Padding 33 byte Multiple Updates")

        iv = nil
        // 1
        plainText  = "0a"
        cipherText = "27cae51ac763b250945fd805c937119b"
        retval = try cryptTest(keyStr: keyStr, ivStr: iv, alg: alg, options: options, cipherText: cipherText, plainText: plainText, log: true)
        XCTAssert(retval, "CBC with Padding 1 byte CCCrypt NULL IV")
        retval = multiCryptTest(keyStr: keyStr, ivStr: iv, alg: alg, options: options, cipherText: cipherText, plainText: plainText)
        XCTAssert(retval, "CBC with Padding 1 byte Multiple Updates NULL IV")

        // 15
        plainText  = "0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a"
        cipherText = "feb9c3a005dcbd1e2630af742e988e81"
        retval = try cryptTest(keyStr: keyStr, ivStr: iv, alg: alg, options: options, cipherText: cipherText, plainText: plainText, log: true)
        XCTAssert(retval, "CBC with Padding 15 byte CCCrypt NULL IV")
        retval = multiCryptTest(keyStr: keyStr, ivStr: iv, alg: alg, options: options, cipherText: cipherText, plainText: plainText)
        XCTAssert(retval, "CBC with Padding 15 byte Multiple Updates NULL IV")

        // 16
        plainText  = "0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a"
        cipherText = "d307b25d3abaf87c0053e8188152992a8b002a94911ee1e157d815a026cfadeb"
        retval = try cryptTest(keyStr: keyStr, ivStr: iv, alg: alg, options: options, cipherText: cipherText, plainText: plainText, log: true)
        XCTAssert(retval, "CBC with Padding 16 byte CCCrypt NULL IV")
        retval = multiCryptTest(keyStr: keyStr, ivStr: iv, alg: alg, options: options, cipherText: cipherText, plainText: plainText)
        XCTAssert(retval, "CBC with Padding 16 byte Multiple Updates NULL IV")

        // 17
        plainText  = "0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a"
        cipherText = "d307b25d3abaf87c0053e8188152992ab8fe4130b613e93617b2eda2e0c5c678"
        retval = try cryptTest(keyStr: keyStr, ivStr: iv, alg: alg, options: options, cipherText: cipherText, plainText: plainText, log: true)
        XCTAssert(retval, "CBC with Padding 17 byte CCCrypt NULL IV")
        retval = multiCryptTest(keyStr: keyStr, ivStr: iv, alg: alg, options: options, cipherText: cipherText, plainText: plainText)
        XCTAssert(retval, "CBC with Padding 17 byte Multiple Updates NULL IV")

        // 31
        plainText  = "0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a"
        cipherText = "d307b25d3abaf87c0053e8188152992a4157ad665141a79481f463357707f759"
        retval = try cryptTest(keyStr: keyStr, ivStr: iv, alg: alg, options: options, cipherText: cipherText, plainText: plainText, log: true)
        XCTAssert(retval, "CBC with Padding 31 byte CCCrypt NULL IV")
        retval = multiCryptTest(keyStr: keyStr, ivStr: iv, alg: alg, options: options, cipherText: cipherText, plainText: plainText)
        XCTAssert(retval, "CBC with Padding 31 byte Multiple Updates NULL IV")

        // 32
        plainText  = "0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a"
        cipherText = "d307b25d3abaf87c0053e8188152992a923832530aa268661a6c1fa3c69d6a23dc6d5c0d7fa8127cfd601cae71b4c14f"
        retval = try cryptTest(keyStr: keyStr, ivStr: iv, alg: alg, options: options, cipherText: cipherText, plainText: plainText, log: true)
        XCTAssert(retval, "CBC with Padding 32 byte CCCrypt NULL IV")
        retval = multiCryptTest(keyStr: keyStr, ivStr: iv, alg: alg, options: options, cipherText: cipherText, plainText: plainText)
        XCTAssert(retval, "CBC with Padding 32 byte Multiple Updates NULL IV")

        // 33
        plainText  = "0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a"
        cipherText = "d307b25d3abaf87c0053e8188152992a923832530aa268661a6c1fa3c69d6a2382178b537aa2946f7a4124ee33744edd"
        retval = try cryptTest(keyStr: keyStr, ivStr: iv, alg: alg, options: options, cipherText: cipherText, plainText: plainText, log: true)
        XCTAssert(retval, "CBC with Padding 33 byte CCCrypt NULL IV")
        retval = multiCryptTest(keyStr: keyStr, ivStr: iv, alg: alg, options: options, cipherText: cipherText, plainText: plainText)
        XCTAssert(retval, "CBC with Padding 33 byte Multiple Updates NULL IV")

        // 34 case test 1 repeated with wrong key size - negative test - don't let CCCryptTestCase() to print error messages on the console
        let keyStr_incorrect = keyStr + "01"
        plainText  = "0a"
        cipherText = "a385b047a4108a8748bf96b435738213"
        retval = try cryptTest(keyStr: keyStr_incorrect, ivStr: iv, alg: alg, options: options, cipherText: cipherText, plainText: plainText, log: false)
        XCTAssert(!retval, "CBC with wrong key size")

        // Blowfish vector that was failing for Jim

        alg = .blowfish
        options = []
        keyStr = "0123456789ABCDEFF0E1D2C3B4A59687"
        iv = "FEDCBA9876543210"
        plainText =  "37363534333231204E6F77206973207468652074696D6520666F722000000000"
        cipherText = "6B77B4D63006DEE605B156E27403979358DEB9E7154616D959F1652BD5FF92CC"
        retval = try cryptTest(keyStr: keyStr, ivStr: iv, alg: alg, options: options, cipherText: cipherText, plainText: plainText, log: true)
        XCTAssert(retval, "CBC-blowfish vector 1")
        retval = multiCryptTest(keyStr: keyStr, ivStr: iv, alg: alg, options: options, cipherText: cipherText, plainText: plainText)
        XCTAssert(retval, "CBC-blowfish vector 1")
    }

}

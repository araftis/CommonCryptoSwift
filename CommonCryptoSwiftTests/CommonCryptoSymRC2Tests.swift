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

/*
 CommonCryptoSwiftTests.swift
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
@testable import CommonCryptoSwift

class CommonCryptoSwiftTests: XCTestCase {

    func testECB() throws {
        var plainText: String
        var cipherText: String
        var retval : Bool
        let keyStr = "000102030405060708090a0b0c0d0e0f"
        let alg = Cryptor.Algorithm.aes
        let options : Cryptor.Options = [.ecbMode]

        // 16
        plainText  = "0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a"
        cipherText = "d307b25d3abaf87c0053e8188152992a"
        retval = try cryptTest(keyStr: keyStr, ivStr: nil, alg: alg, options: options, cipherText: cipherText, plainText: plainText, log: true)
        XCTAssert(retval, "ECB with Padding 16 byte CCCrypt NULL IV")
        retval = multiCryptTest(keyStr: keyStr, ivStr: nil, alg: alg, options: options, cipherText: cipherText, plainText: plainText)
        XCTAssert(retval, "ECB with Padding 16 byte Multiple Updates NULL IV")

        // 32
        plainText  = "0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a";
        cipherText = "d307b25d3abaf87c0053e8188152992ad307b25d3abaf87c0053e8188152992a";
        retval = try cryptTest(keyStr: keyStr, ivStr: nil, alg: alg, options: options, cipherText: cipherText, plainText: plainText, log: true)
        XCTAssert(retval, "ECB 32 byte CCCrypt NULL IV");
        retval = multiCryptTest(keyStr: keyStr, ivStr: nil, alg: alg, options: options, cipherText: cipherText, plainText: plainText)
        XCTAssert(retval, "ECB 32 byte Multiple Updates NULL IV")
    }

}

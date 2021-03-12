#  CommonCryptoSwift

## Overview

This 99% a frontend to Apple's CommonCrypto framework. You can find the [source code](https://opensource.apple.com/source/CommonCrypto/) for that framework at Apple's open source repository. The remaining 1% are some conveneinces on String and Data for performing basic hashing and cyptography operations. I should have covers for all functionality of CommonCrypto. Let me know if I'm missing anything, and I'll see about adding it.

This was written for my CalPoly CSC 321 (Software Security) course, because I wanted to use Swift as my primary language for development. When I attempted to do that, I found that trying to access CommonCryptor from Swift was somewhat awkward at best, and mildly painful at worse. To that end, I wrote a simple Swift wrapper that makes accessing the CommonCrypto functions much easier to use.

This simplifies much of the calls into the library. For example, simple one shot encryption / decryption can be done as follows:

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

## Author

The initial implementation was created by AJ Raftis <araftis@calpoly.edu>. This was created for my CSC 321 Software Security course.

## Classes

Cryptor
: The main cover class for the library. This is where you'll spend much of your time. Also contains the various enumerations and constants used by the library.

CommonDigest
: The protocol to define the interface for creation cryptographic hashes. Implemented by MD2, MD4, MD5, SHA1, SHA224, SHA256, SHA384, and SHA512 classes.

Hmac
: Covers the CommonHmac functions.

## Platforms

As of the initial writing, I've only made sure this works on macOS. Most of the code should compile on other platforms, however, some of the conveniences on Data require Apple's Security framework (uses SecRandomCopyBytes), and would need to be adaptor for other platforms. If you'd like to add the necessary support for compiling on Linux (or Windows) let me know, and I'll happily accept a push request.

## Feedback

While I'm pretty good with Swift, I'm sure some of my API choices could be debated. Let me know what you think. I'm open to suggestions for improving the API.

## Unit Testing

I've ported a number of the unit tests over from the original project to Swift. These all use the Swift API's, and are primarily designed to test the functionality of the wrapper. I'm making the assumption that the underlying framework is sufficiently tested, that we don't need to duplicate that specific work. Again, feel free to submit additional unit tests.

## License

I'm releasing this under a BSD license.

```
Copyright (c) 2021, AJ Raftis
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:
* Redistributions of source code must retain the above copyright notice, this 
  list of conditions and the following disclaimer.
* Redistributions in binary form must reproduce the above copyright notice, 
  this list of conditions and the following disclaimer in the documentation 
  and/or other materials provided with the distribution.
* Neither the name of the AJ Raftis nor the names of its contributors may be 
  used to endorse or promote products derived from this software without 
  specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND 
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED 
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE 
DISCLAIMED. IN NO EVENT SHALL AJ Raftis BE LIABLE FOR ANY DIRECT, INDIRECT, 
INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT 
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR 
PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF 
LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE 
OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF 
ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
```


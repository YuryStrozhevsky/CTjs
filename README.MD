# CTjs

CTjs is a full set of classes necessary to work with any kind of Certificate Transparency log (V1 as from RFC6962, or V2 as from RFC6962-bis). In CTjs you could find all necessary validation/verification functions for all related data shipped with full-featured examples showning how to validate/verify. Also in scope of CTjs I made code showing example from RFC6962 item 2.1.3 on a real data from real Certificate Transparency log.  

## Features

* Ability to work in both Node and browser environment;
* Pure ES6 code and examples;
* All you need to deal with Certificate Transparency logs V1 (RFC6962);
* All you need to deal with Certificate Transparency logs V2 (RFC6962-bis);
* All algorithms from RFC6962-bis implemented in pure JavaScript (MTH, PROOF, SUBPROOF, PATH, all verification algorithms and more);
* Merkle Tree realization having all functions like making/verifiying inclusion proof, making/verifiying consistency and many more;
* Signed Certificate Timestamp verification;
* Signed Tree Head verification;
* Calculation of tree head hash on any previous tree size (algorithm based on inclusion proof);
* Verification of internal CT extension in X.509 certificate (pre-certificate verification);
* Full-featured example from RFC6962 on a real data from all known CT logs;
* Full-featured examples showing how to build real monitor/auditor for any Certificate Transparency log;

## Examples

### How to verify Signed Tree Head (STH)

```javascript
const sth = await log.get_sth();
const sthVerificationResult = await sth.verify(log.key);
```

### How to verify SCT Extension in Certificate

```javascript
const sctForVerification = sctFromCertificate(entry.leaf.entry.signedEntry, sct.logID);
if(sctForVerification !== null)
{
    const issuer = await findIssuer(entry.leaf.entry.signedEntry, entry.extra_data);

    const preCertificate = await PreCert.fromCertificateAndIssuer({
        certificate: entry.leaf.entry.signedEntry,
        issuer: issuer
    });
    
    const sctVerificationResult = await sctForVerification.verify(preCertificate.buffer, log.key, LogEntryType.constants("precert_entry"));
}
```

### How to verify Precertificate you got from CT Log

```javascript
sct = await log.add_pre_chain([
    entry.extra_data.pre_certificate,
    ...entry.extra_data.precertificate_chain
]);

const issuer = await findIssuer(entry.extra_data.pre_certificate, entry.extra_data.precertificate_chain);

const preCert = await PreCert.fromCertificateAndIssuer({
    certificate: entry.extra_data.pre_certificate,
    issuer
});

data = preCert.buffer;

const sctVerificationResult = await sct.verify(
    data,
    log.key,
    entry.leaf.entry.entryType
);
```

### How to verify proof of inclusion

```javascript
const proof_d0 = await log.get_proof_by_hash(entries[0].leaf, 7);
const verificationProof_d0 = await utils.verifyInclusionProof(
    stringToArrayBuffer(fromBase64(a)),
    0,
    7,
    stringToArrayBuffer(fromBase64(hash)),
    proof_d0.audit_path
);
```

### How to verify consistency

```javascript
const consistency1_7 = await log.get_sth_consistency(1, 7);
const verificationConsistency1_7 = await utils.verifyConsistency(
    1,
    stringToArrayBuffer(fromBase64(a)),
    7,
    stringToArrayBuffer(fromBase64(calculatedRootHashesBase64[5])),
    consistency1_7
);
```

## Limitations

At the moment code in CTjs uses 32-bit binary operations. That is why currectly CTjs limited working only with "tree size < 2^32". Having CTjs code to work with bigger sizes is a subject for future development. Also need to say that I do not expect any real Certificate Transparency log to operate more than 4 billion entries in next few years - it is too hard to operate with such huge database, usually CT log would end its life at some tree size and new CT log would be launched.  Thus you should not worry about CTjs limitations - all would work fine at least few years.

## Related source code

* [_**ASN1.js**_](https://github.com/PeculiarVentures/ASN1.js) - ASN.1 parser/maker on pur JavaScript (BER encoding/decoding);
* [_**PKI.js**_](https://github.com/PeculiarVentures/PKI.js) - PKIjs is a pure JavaScript library implementing the formats that are used in PKI applications (signing, encryption, certificate requests, OCSP and TSP requests/responses). It is built on WebCrypto (Web Cryptography API) and requires no plug-ins;
* [_**ByteStream.js**_](https://github.com/PeculiarVentures/ByteStream.js) - ByteStream.js is a set of classes manipulating bytes and bits with optimized for speed perfomance;
* [_**pvutils**_](https://github.com/PeculiarVentures/pvutils) - pvutils is a set of common utility functions used in various Peculiar Ventures Javascript based projects;

## License

*Copyright (c) 2018 [_**Yury Strozhevsky**_](http://www.strozhevsky.com/).*
*All rights reserved.*

Redistribution and use in source and binary forms, with or without modification, 
are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, 
   this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, 
   this list of conditions and the following disclaimer in the documentation 
   and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its contributors 
   may be used to endorse or promote products derived from this software without 
   specific prior written permission.

*THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND 
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED 
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. 
IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, 
INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT 
NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR 
PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, 
WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) 
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY 
OF SUCH DAMAGE.* 
 
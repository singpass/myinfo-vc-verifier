# MyInfo VC Verifier

MyInfo VC Verifier aims to simplify consumer's integration effort with MyInfoBiz Corporate VC.
This package provides the functionality to verify a verifiable credential using @mattrglobal jsonld-signatures-bbs.

![latest version](https://img.shields.io/github/package-json/v/singpass/myinfo-vc-verifier) ![ci workflow](https://img.shields.io/github/actions/workflow/status/singpass/myinfo-vc-verifier/ci.yml)

## Contents

- [Install](#install)
- [Usage](#usage)
- [Change Logs](https://github.com/singpass/myinfo-vc-verifier/blob/master/CHANGELOG.md)

## Install

### NPM

To install via NPM:

```
npm install myinfo-vc-verifier
```

## Usage

```
var MyInfoVcVerifier = require('myinfo-vc-verifier');
```

### Verify

This method takes in the verifiable credential to verify and return true/false.

```
/**
 * [Verify Verifiable Credential]
 * @param  {Object} signedDocument [signed verifiable credential OR signed verifiable Presentation]
 * @param  {Object} OPTIONAL: Array of context object [context object]
 * @return {Promise} Promise object represents verification result [verified status]
 */
MyInfoVcVerifier.verify(signedDocument, customDocuments) // { verified: true, results: [ { proof: [Object], verified: true } ] }
```

### Get Revoke Status

Performs revocation status checks on the VC's credentialStatus and return true/false.

```
/**
 * [Get Revoke Status]
 * @param  {Object} signedVC [verifiable credential]
 * @param  {Object} OPTIONAL - opts: {"refreshCache": true | false} Default to false
 * @return {Promise} Promise object represents Boolean [the revoke status]
 */
MyInfoVcVerifier.getRevokeStatus(signedVC, opts) // true/false
```

### Signing Ethereum

Generates signature for code challenges. Returns String.

```
/**
 * [Ethereum Signing Message]
 * @param  {Object} privateKey [the private key]
 * @param  {Object} message [the message]
 * @return {String}      [the signature]
 */
MyInfoVcVerifier.ethereumSign(privateKey, message);
```

## Reporting Issue

You may contact our [support](mailto:support@myinfo.gov.sg?subject=[MyInfoVcVerifier-NodeJs]%20Issue%20) for any other technical issues, and we will respond to you within 5 working days.

# MyInfo VC Verifier

[![Known Vulnerabilities](https://snyk.io/test/github/singpass/myinfo-vc-verifier/badge.svg)](https://snyk.io/test/github/singpass/myinfo-vc-verifier)

MyInfo VC Verifier aims to simplify consumer's integration effort with MyInfoBiz Corporate VC.
This package provides the functionality to verify a verifiable credential using @mattrglobal jsonld-signatures-bbs.

## Contents

- [Install](#install)
- [Usage](#usage)
- [Change Logs](./CHANGELOG.md)

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
 * @param  {[Object]} signedVC [verifiable credential]
 * @return {[Boolean]}      [verified status]
 */
MyInfoVcVerifier.verify(signedVC); //true/false
```

### Get Revoke Status
Performs revocation status checks on the VC's credentialStatus and return true/false.
```
/**
 * [Get Revoke Status]
 * @param  {[Object]} signedVC [signed verifiable credential]
 * @return {[Boolean]}      [the revoke status]
 */
MyInfoVcVerifier.getRevokeStatus(signedVC); // true/false
```

## Reporting Issue

You may contact our [support](mailto:support@myinfo.gov.sg?subject=[MyInfoLib-NodeJs]%20Issue%20) for any other technical issues, and we will respond to you within 5 working days.

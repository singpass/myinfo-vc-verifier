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

```
MyInfoVcVerifier.verify(verifiableCredential);
//
```

### Get Revoke Status

```
MyInfoVcVerifier.getRevokeStatus(verifiableCredential); // true/false
```

## Reporting Issue

You may contact our [support](mailto:support@myinfo.gov.sg?subject=[MyInfoLib-NodeJs]%20Issue%20) for any other technical issues, and we will respond to you within 5 working days.

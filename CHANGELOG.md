# Changelog

## 0.1.1 11 Oct 2023:

- Add static w3 credentials v1 context file to default documents

## 0.1.0 22 Sept 2023:

- Add in VP and VC verification for did:key to ensure VC did:key matches with VP did:key

## 0.0.8 11 Sep 2023:

- Add getExpirationStatus function

## 0.0.7 22 Aug 2023:

- Fix test stub data
- Update npm @cypress/request to @3.0.0

## 0.0.6 12 Jul 2023:

- Fix getRevokeStatus function to parseInt for statusListIndex if it is a String
- Change test files

## 0.0.5 25 May 2023:

- Add LICENSE file
- Added cache functionality to context documents and revoke status
- Change verify function to add OPTIONAL customDocuments
- Change getRevokeStatus to add OPTIONAL opts to allow refreshCache

## 0.0.4 22 May 2023:

- Add verify Verifiable Presentation function
- Add verify Verifiable Credential function
- Change verify function to allow verification of Verifiable Credential, Verifiable Presentation and Selective Disclosed Verifiable Credential
- Add and change test cases for new functions

## 0.0.3 01 Mar 2023:

- Add unit testing and git workflow for CI

## 0.0.2 31 Jan 2023:

- Update readme.md and fix revoke getEncodedList function
- Publish to NPM

## 0.0.1 04 Jan 2023:

- Initial release of the myinfo-vc-verifier library

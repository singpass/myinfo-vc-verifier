const jsonldSignatures = require("jsonld-signatures");
const { https } = require("follow-redirects");
const bs = require("@transmute/compressable-bitstring");
const bbs = require("@mattrglobal/jsonld-signatures-bbs");
const ethereumjs = require("ethereumjs-util");
const didkit = require("@spruceid/didkit-wasm-node");
const bs58 = require("bs58");

let documents = {
  "https://w3id.org/security/bbs/v1": require("./contextData/w3id-sec-bbs-v1.json"),
  "https://w3id.org/did/v0.11": require("./contextData/w3id-did-v0.11.json"),
};

let MyInfoVcVerifier = {};

let revokeStatusCache = {};

/**
 * [Get Document Loader]
 * @param  {Object} OPTIONAL: Array of context object [context object]
 * @return {Promise} [documentloader]
 */
async function getDocumentLoader(customDocuments = []) {
  const customDocLoader = async (url) => {
    return new Promise(async (resolve, reject) => {
      if (customDocuments[url] || documents[url]) {
        // Fix missing context
        let resolveContext = {
          contextUrl: null, // this is for a context via a link header
          document: customDocuments[url] || documents[url], // this is the actual document that was loaded
          documentUrl: url, // this is the actual context URL after redirects
        };

        resolve(resolveContext);
        return;
      }
      let httpsURL = url;
      if (url.includes("did:key")) {
        if (url.includes("#")) {
          httpsURL = httpsURL.slice(0, httpsURL.indexOf("#"));
        }
        const didDocument = await didKeyResolver(httpsURL);
        let resolveContext = {
          contextUrl: null, // this is for a context via a link header
          document: didDocument, // this is the actual document that was loaded
          documentUrl: httpsURL, // this is the actual context URL after redirects
        };
        documents[url] = didDocument;
        resolve(resolveContext);
        return;
      }
      if (url.includes("did:web")) {
        if (url.includes("#")) {
          httpsURL = httpsURL.slice(0, httpsURL.indexOf("#"));
        }
        const id = httpsURL.split(":");
        let path = id.map(decodeURIComponent).join("/") + "/did.json";
        httpsURL = path.replace("did/web/", "https://");
      }
      let data = [];
      https
        .get(httpsURL, (response) => {
          response.on("data", (chunk) => {
            data.push(chunk);
          });
          response.on("end", () => {
            let resolveContext = {
              contextUrl: null, // this is for a context via a link header
              document: JSON.parse(Buffer.concat(data).toString()), // this is the actual document that was loaded
              documentUrl: response.responseUrl, // this is the actual context URL after redirects
            };
            documents[url] = JSON.parse(Buffer.concat(data).toString());
            resolve(resolveContext);
          });
        })
        .on("error", (err) => {
          reject(err);
        });
    });
  };
  return jsonldSignatures.extendContextLoader(customDocLoader);
}

// did:key resolver for Ed25519 key
async function didKeyResolver(did) {
  let didDocument = await didkit.resolveDID(did, "{}");
  didDocument = JSON.parse(didDocument);
  let publicKey = Buffer.from(didDocument.verificationMethod[0].publicKeyJwk.x, "base64url");
  let publicKeyBase58 = bs58.encode(publicKey);

  let publicKeyItem = {
    controller: didDocument.verificationMethod[0].controller,
    id: didDocument.verificationMethod[0].id,
    type: didDocument.verificationMethod[0].type,
    publicKeyBase58: publicKeyBase58,
  };
  let context = ["https://w3id.org/did/v0.11"];
  let cloneDocument = {
    id: didDocument.id,
    assertionMethod: didDocument.assertionMethod,
    "@context": context,
    verificationMethod: [publicKeyItem],
  };
  return cloneDocument;
}

/**
 * [Get & Verify Encoded List from Verifiable Credential]
 * @param  {Object} signedVC [signed verifiable credential]
 * @return {Promise} Promise object represents a String [verified encoded list]
 */
MyInfoVcVerifier.getEncodedList = async function (signedVC, opts) {
  return new Promise((resolve, reject) => {
    let data = [];
    let encodedList = "";
    let statusUrl = signedVC["credentialStatus"]["id"].split("#")[0];

    if (revokeStatusCache[statusUrl]) {
      if (opts?.refreshCache) {
        https
          .get(statusUrl, (response) => {
            response.on("data", (chunk) => {
              data.push(chunk);
            });
            response.on("end", async () => {
              let cs = JSON.parse(Buffer.concat(data).toString());

              let verifiedCS = await this.verify(cs);
              if (verifiedCS.verified) {
                encodedList = cs.credentialSubject.encodedList;
              } else {
                reject("ERROR: Fail to verify credentialStatus");
              }
              revokeStatusCache[statusUrl] = encodedList;
              resolve(encodedList);
            });
          })
          .on("error", (err) => {
            reject(err);
          });
      } else {
        resolve(revokeStatusCache[statusUrl]);
      }
    } else {
      https
        .get(statusUrl, (response) => {
          response.on("data", (chunk) => {
            data.push(chunk);
          });
          response.on("end", async () => {
            let cs = JSON.parse(Buffer.concat(data).toString());

            let verifiedCS = await this.verify(cs);
            if (verifiedCS.verified) {
              encodedList = cs.credentialSubject.encodedList;
            } else {
              reject("ERROR: Fail to verify credentialStatus");
            }
            revokeStatusCache[statusUrl] = encodedList;
            resolve(encodedList);
          });
        })
        .on("error", (err) => {
          reject(err);
        });
    }
  });
};

/**
 * [Verify Verifiable Credential]
 * @param  {Object} signedDocument [signed verifiable credential OR signed verifiable Presentation]
 * @param  {Object} OPTIONAL: Array of context object [context object]
 * @return {Promise} Promise object represents verification result [verified status]
 */
MyInfoVcVerifier.verify = async function (signedDocument, customDocuments) {
  if (signedDocument.type.includes("VerifiableCredential")) {
    // Verify credential
    return this.verifyCredential(signedDocument, customDocuments);
  } else if (signedDocument.type.includes("VerifiablePresentation")) {
    let result = await this.verifyPresentation(signedDocument, customDocuments);
    if (result.verified) {
      let credentials = signedDocument.verifiableCredential;
      let verifyPromises = [];
      for (let credential of credentials) {
        verifyPromises.push(this.verifyCredential(credential, customDocuments));
      }
      let results = await Promise.all(verifyPromises);
      return results;
    } else {
      return result;
    }
  }
};

/**
 * [Verify Verifiable Credential]
 * @param  {Object} Verifiable Credential object [signed verifiable credential]
 * @param  {Object} OPTIONAL: Array of context object [context object]
 * @return {Promise} Promise object represents verification result [verified status]
 */
MyInfoVcVerifier.verifyCredential = async function (credential, customDocuments) {
  let documentLoader = await getDocumentLoader(customDocuments);
  let suite = [new bbs.BbsBlsSignature2020(), new bbs.BbsBlsSignatureProof2020()];

  return await jsonldSignatures.verify(credential, {
    suite: suite,
    purpose: new jsonldSignatures.purposes.AssertionProofPurpose(),
    documentLoader,
  });
};

/**
 * [Verify Verifiable Presentation]
 * @param  {Object} Verifiable Presentation object [signed verifiable presentation]
 * @param  {[Object]} OPTIONAL: Array of context object [context object]
 * @return {Promise} Promise object represents verification result [verified status]
 */
MyInfoVcVerifier.verifyPresentation = async function (presentation, customDocuments) {
  let documentLoader = await getDocumentLoader(customDocuments);
  const result = await jsonldSignatures.verify(presentation, {
    suite: new jsonldSignatures.suites.Ed25519Signature2018(),
    purpose: new jsonldSignatures.purposes.AssertionProofPurpose(),
    documentLoader,
  });
  return result;
};

/**
 * [Check Revoke Status]
 * @param  {Object} encoded [the verified encoded list]
 * @param  {Number} listIndex [the status list index]
 * @return {Promise} Promise object represents Boolean [the revoke status]
 */
async function checkRevokeStatus(encoded, listIndex) {
  let decodedList = await bs.Bitstring.decodeBits({ encoded });
  const bitstring = new bs.Bitstring({ buffer: decodedList });
  let result = bitstring.get(listIndex);
  return result;
}

/**
 * [Get Revoke Status]
 * @param  {Object} signedVC [verifiable credential]
 * @param  {Object} OPTIONAL - opts: {"refreshCache": true | false} Default to false
 * @return {Promise} Promise object represents Boolean [the revoke status]
 */
MyInfoVcVerifier.getRevokeStatus = async function (signedVC, opts) {
  let encoded = await this.getEncodedList(signedVC, opts);
  let result = await checkRevokeStatus(encoded, signedVC.credentialStatus.statusListIndex);

  return result;
};

/**
 * [Ethereum Signing Message]
 * @param  {Object} privateKey [the private key]
 * @param  {Object} message [the message]
 * @return {String}      [the signature]
 */
MyInfoVcVerifier.ethereumSign = function (privateKey, message) {
  let hash = ethereumjs.hashPersonalMessage(Buffer.from(message));
  let keyBuffer = Buffer.from(privateKey, "hex");

  let signature = ethereumjs.ecsign(hash, keyBuffer);
  let rpcSignature = ethereumjs.toRpcSig(signature.v, signature.r, signature.s);
  return rpcSignature.substring(2, rpcSignature.length);
};

module.exports = MyInfoVcVerifier;

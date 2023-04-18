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

/**
 * [Get Document Loader]
 * @param  {[String]} url [context url]
 * @return {[Object]}      [documentloader]
 */
async function getDocumentLoader() {
  const customDocLoader = async (url) => {
    return new Promise(async (resolve, reject) => {
      if (documents[url]) {
        // Fix missing context
        let resolveContext = {
          contextUrl: null, // this is for a context via a link header
          document: documents[url], // this is the actual document that was loaded
          documentUrl: url, // this is the actual context URL after redirects
        };
        resolve(resolveContext);
        return;
      }
      if (url.includes("did:key")) {
        if (url.includes("#")) {
          url = url.slice(0, url.indexOf("#"));
        }
        const didDocument = await didKeyResolver(url);
        let resolveContext = {
          contextUrl: null, // this is for a context via a link header
          document: didDocument, // this is the actual document that was loaded
          documentUrl: url, // this is the actual context URL after redirects
        };
        resolve(resolveContext);
        return;
      }
      if (url.includes("did:web")) {
        if (url.includes("#")) {
          url = url.slice(0, url.indexOf("#"));
        }
        const id = url.split(":");
        let path = id.map(decodeURIComponent).join("/") + "/did.json";
        url = path.replace("did/web/", "https://");
      }
      let data = [];
      https
        .get(url, (response) => {
          response.on("data", (chunk) => {
            data.push(chunk);
          });
          response.on("end", () => {
            let resolveContext = {
              contextUrl: null, // this is for a context via a link header
              document: JSON.parse(Buffer.concat(data).toString()), // this is the actual document that was loaded
              documentUrl: response.responseUrl, // this is the actual context URL after redirects
            };
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
 * @param  {[Object]} signedVC [signed verifiable credential]
 * @return {[String]}      [verified encoded list]
 */
MyInfoVcVerifier.getEncodedList = async function (signedVC) {
  return new Promise((resolve, reject) => {
    let data = [];
    let encodedList = "";
    https
      .get(signedVC["credentialStatus"]["id"], (response) => {
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

          resolve(encodedList);
        });
      })
      .on("error", (err) => {
        reject(err);
      });
  });
};

/**
 * [Verify Verifiable Credential]
 * @param  {[Object]} signedDocument [signed verifiable credential OR signed verifiable Presentation]
 * @return {[Object]}      [verified status]
 */
MyInfoVcVerifier.verify = async function (signedDocument) {
  if (signedDocument.type.includes("VerifiableCredential")) {
    // Verify credential
    return this.verifyCredential(signedDocument);
  } else if (signedDocument.type.includes("VerifiablePresentation")) {
    let result = await this.verifyPresentation(signedDocument);
    if (result.verified) {
      let credentials = signedDocument.verifiableCredential;
      let verifyPromises = [];
      for (let credential of credentials) {
        verifyPromises.push(this.verifyCredential(credential));
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
 * @param  {[Object]} credential [signed verifiable credential]
 * @return {[Object]}      [verified status]
 */
MyInfoVcVerifier.verifyCredential = async function (credential) {
  let documentLoader = await getDocumentLoader();

  return await jsonldSignatures.verify(credential, {
    suite: new bbs.BbsBlsSignature2020(),
    purpose: new jsonldSignatures.purposes.AssertionProofPurpose(),
    documentLoader,
  });
};

/**
 * [Verify Verifiable Presentation]
 * @param  {[Object]} presentation [signed verifiable presentation]
 * @return {[Object]}      [verified status]
 */
MyInfoVcVerifier.verifyPresentation = async function (presentation) {
  let documentLoader = await getDocumentLoader();
  const result = await jsonldSignatures.verify(presentation, {
    suite: new jsonldSignatures.suites.Ed25519Signature2018(),
    purpose: new jsonldSignatures.purposes.AssertionProofPurpose(),
    documentLoader,
  });
  return result;
};

/**
 * [Check Revoke Status]
 * @param  {[Object]} encoded [the verified encoded list]
 * @param  {[Number]} listIndex [the status list index]
 * @return {[Boolean]}      [the revoke status]
 */
async function checkRevokeStatus(encoded, listIndex) {
  let decodedList = await bs.Bitstring.decodeBits({ encoded });
  const bitstring = new bs.Bitstring({ buffer: decodedList });
  let result = bitstring.get(listIndex);
  return result;
}

/**
 * [Get Revoke Status]
 * @param  {[Object]} signedVC [verifiable credential]
 * @return {[Boolean]}      [the revoke status]
 */
MyInfoVcVerifier.getRevokeStatus = async function (signedVC) {
  let encoded = await this.getEncodedList(signedVC);
  let result = await checkRevokeStatus(encoded, signedVC.credentialStatus.statusListIndex);

  return result;
};

/**
 * [Ethereum Signing Message]
 * @param  {[Object]} privateKey [the private key]
 * @param  {[Object]} message [the message]
 * @return {[String]}      [the signature]
 */
MyInfoVcVerifier.ethereumSign = function (privateKey, message) {
  let hash = ethereumjs.hashPersonalMessage(Buffer.from(message));
  let keyBuffer = Buffer.from(privateKey, "hex");

  let signature = ethereumjs.ecsign(hash, keyBuffer);
  let rpcSignature = ethereumjs.toRpcSig(signature.v, signature.r, signature.s);
  return rpcSignature.substring(2, rpcSignature.length);
};

module.exports = MyInfoVcVerifier;

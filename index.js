const jsonldSignatures = require("jsonld-signatures");
const { https } = require("follow-redirects");
const bs = require("@transmute/compressable-bitstring");
const bbs = require("@mattrglobal/jsonld-signatures-bbs");
const ethereumjs = require("ethereumjs-util");

let MyInfoVcVerifier = {};

async function getDocumentLoader() {
  const customDocLoader = async (url) => {
    return new Promise((resolve, reject) => {
      //console.log(url);
      if (url.includes("did:")) {
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
            //console.log(response.responseUrl);
            //console.log(JSON.parse(Buffer.concat(data).toString()))
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

MyInfoVcVerifier.getEncodedList = async function (signedVC) {
  return new Promise((resolve, reject) => {
    let data = [];
    https
      .get(signedVC["credentialStatus"]["id"], (response) => {
        response.on("data", (chunk) => {
          data.push(chunk);
        });
        response.on("end", () => {
          let cs = JSON.parse(Buffer.concat(data).toString());
          let encodedList = cs.credentialSubject.encodedList;
          resolve(encodedList);
        });
      })
      .on("error", (err) => {
        reject(err);
      });
  });
};

MyInfoVcVerifier.verify = async function (signedCredential) {
  let documentLoader = await getDocumentLoader();

  return await jsonldSignatures.verify(signedCredential, {
    suite: new bbs.BbsBlsSignature2020(),
    purpose: new jsonldSignatures.purposes.AssertionProofPurpose(),
    documentLoader,
  });
};

async function checkRevokeStatus(encoded, listIndex) {
  let decodedList = await bs.Bitstring.decodeBits({ encoded });
  const bitstring = new bs.Bitstring({ buffer: decodedList });
  console.log("bitstring length: " + bitstring.length);
  let result = bitstring.get(listIndex);
  return result;
}

MyInfoVcVerifier.getRevokeStatus = async function (signedVC) {
  let encoded = await this.getEncodedList(signedVC);
  console.log("encoded:", encoded);
  console.log("listindex:", signedVC.credentialStatus.statusListIndex);
  let result = await checkRevokeStatus(encoded, signedVC.credentialStatus.statusListIndex);

  return result;
};

MyInfoVcVerifier.ethereumSign = function (privateKey, message) {
  let hash = ethereumjs.hashPersonalMessage(Buffer.from(message));
  let keyBuffer = Buffer.from(privateKey, "hex");

  let signature = ethereumjs.ecsign(hash, keyBuffer);
  let rpcSignature = ethereumjs.toRpcSig(signature.v, signature.r, signature.s);
  return rpcSignature.substring(2, rpcSignature.length);
};

module.exports = MyInfoVcVerifier;

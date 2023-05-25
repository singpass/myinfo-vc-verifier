/* istanbul ignore file */
const MyInfoVcVerifier = require("../index.js");

//stub data
const signedVC = require("./stub/signedVC.json");
const invalidVC = require("./stub/invalidVC.json");
const revokedVC = require("./stub/revokedVC.json");
const verifyresult = require("./stub/result.json");
const signedVP = require("./stub/signedVP.json");
const invalidVP = require("./stub/invalidVP.json");
const verifyPresentationResult = require("./stub/resultPresentation.json");
const vpVcResult = require("./stub/resultVPVC.json");
const signedSDVC = require("./stub/signedSelectiveDisclosedVC.json");

let now = new Date().toLocaleString("en-US", {
  timeZone: "Asia/Singapore",
});

let currentDate = new Date(now).toISOString().substring(0, 10);

describe("Test VC verifier", () => {
  let context;
  beforeEach(() => {
    jest.spyOn(console, "error");
    // To escape console error while jest unit testing
    console.error.mockImplementation((message) => console.info(message));

    context = {
      functionName: "mock:myinfo-backend-batch-dev-query-person-data",
      awsRequestId: "mock:awsRequestId",
    };
  });

  afterEach(() => {
    console.error.mockRestore();
    jest.resetAllMocks();
    jest.restoreAllMocks();
  });

  it("should verify VC successfully", async () => {
    const result1 = await MyInfoVcVerifier.verify(signedVC);
    const result2 = await MyInfoVcVerifier.verifyCredential(signedVC);

    expect(result1).toStrictEqual(verifyresult);
    expect(result2).toStrictEqual(verifyresult);
  }, 15000);

  it("should verify VC successfully with custom documents", async () => {
    let customDocuments = {
      "did:web:dev.issuer.myinfo.gov.sg:myinfobusiness": require("../contextData/myinfobusiness-did.json"),
    };
    const result1 = await MyInfoVcVerifier.verify(signedVC, customDocuments);

    expect(result1).toStrictEqual(verifyresult);
  }, 5000);

  it("should validate revoke status successfully", async () => {
    const result = await MyInfoVcVerifier.getRevokeStatus(signedVC);

    expect(result).toStrictEqual(false);
  }, 5000);

  it("should verify VC fail", async () => {
    const result1 = await MyInfoVcVerifier.verify(invalidVC);
    const result2 = await MyInfoVcVerifier.verifyCredential(invalidVC);

    expect(result1.verified).toStrictEqual(false);
    expect(result2.verified).toStrictEqual(false);
  }, 5000);

  it("should validate revoke status as revoked", async () => {
    const result = await MyInfoVcVerifier.getRevokeStatus(revokedVC, { refreshCache: true });

    expect(result).toStrictEqual(true);
  }, 5000);

  it("should verify VP successfully", async () => {
    const result = await MyInfoVcVerifier.verifyPresentation(signedVP);

    expect(result).toStrictEqual(verifyPresentationResult);
  }, 5000);

  it("should verify VP fail", async () => {
    const result = await MyInfoVcVerifier.verifyPresentation(invalidVP);

    expect(result.verified).toStrictEqual(false);
  }, 5000);

  it("should verify VP and VC successfully", async () => {
    const result = await MyInfoVcVerifier.verify(signedVP);
    expect(result).toStrictEqual(vpVcResult);
  }, 5000);

  it("should verify selective disclosed VC successfully", async () => {
    const result = await MyInfoVcVerifier.verify(signedSDVC);
    expect(result.verified).toStrictEqual(true);
  }, 5000);
});

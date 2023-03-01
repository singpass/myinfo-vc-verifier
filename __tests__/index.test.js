/* istanbul ignore file */
const MyInfoVcVerifier = require('../index.js');

//stub data
const signedVC = require('./signedVC.json');
const invalidVC = require('./invalidVC.json');
const revokedVC = require('./revokedVC.json');
const verifyresult = require("./result.json");
const verifyresultfail = require("./result-bad.json");

let now = new Date().toLocaleString('en-US', {
  timeZone: 'Asia/Singapore',
});

let currentDate = new Date(now).toISOString().substring(0, 10);

describe('Test VC verifier', () => {
  let context;
  beforeEach(() => {
    jest.spyOn(console, 'error');
    // To escape console error while jest unit testing
    console.error.mockImplementation((message) => console.info(message));

    context = {
      functionName: 'mock:myinfo-backend-batch-dev-query-person-data',
      awsRequestId: 'mock:awsRequestId',
    };
  });

  afterEach(() => {
    console.error.mockRestore();
    jest.resetAllMocks();
    jest.restoreAllMocks();
  });

  it('should verify VC successfully', async () => {

    const result = await MyInfoVcVerifier.verify(signedVC);

    let testRes = verifyresult;

    expect(result).toStrictEqual(testRes);
  }, 10000);

  it('should validate revoke status successfully', async () => {

    const result = await MyInfoVcVerifier.getRevokeStatus(signedVC);

    expect(result).toStrictEqual(false);
  }, 10000);

  it('should verify VC fail', async () => {

    const result = await MyInfoVcVerifier.verify(invalidVC);

    expect(result.verified).toStrictEqual(false);
  }, 10000);

  it('should validate revoke status as revoked', async () => {

    const result = await MyInfoVcVerifier.getRevokeStatus(revokedVC);

    expect(result).toStrictEqual(true);
  }, 10000);
});

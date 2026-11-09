import jwt from 'jsonwebtoken';
import type { Request, Response } from 'express';
import type { EnrollmentControllerDependencies } from './enrollment';
import type { StoredTwoFactorAccount } from './twoFactor';
import {
  TWO_FACTOR_TOKEN_PURPOSE,
  generateTwoFactorLoginChallengeToken,
  generateTwoFactorSetupToken,
  requireTwoFactorSetupToken,
  requireTwoFactorSetupAcknowledgementToken,
  requireTwoFactorSetupFinalizationToken,
} from './twoFactor';
import { createEnrollmentControllers } from './enrollment';

const USER_ID = 'user-1';
const BROWSER_REFRESH_TOKEN = 'this-browser-refresh-token';
const OTHER_BROWSER_REFRESH_TOKEN = 'other-browser-refresh-token';
const FUTURE = new Date(Date.now() + 60 * 60 * 1000);

interface StoredSession {
  _id: string;
  user: string;
  refreshToken: string;
  expiration: Date;
}

function createResponse() {
  const res = {
    status: jest.fn().mockReturnThis(),
    json: jest.fn().mockReturnThis(),
    clearCookie: jest.fn().mockReturnThis(),
  };
  return res as typeof res & Response;
}

/**
 * In-memory account and session stores with the compare-and-swap semantics of the Mongo-backed
 * methods, so the controller runs against real lifecycle state instead of canned replies.
 */
function createHarness(overrides: Partial<StoredTwoFactorAccount> = {}) {
  let doc: StoredTwoFactorAccount = {
    _id: USER_ID,
    provider: 'local',
    tenantId: 'tenant-a',
    storageRegion: 'eu-central-1',
    twoFactorEnabled: false,
    totpSecret: undefined,
    backupCodes: [],
    pendingTotpSecret: 'encrypted-secret',
    pendingBackupCodes: [{ codeHash: 'staged-hash', used: false }],
    twoFactorAcknowledgementNonceHash: 'ack-hash',
    twoFactorFinalizationNonceHash: 'finalization-hash',
    ...overrides,
  };
  const sessions: StoredSession[] = [
    { _id: 'session-1', user: USER_ID, refreshToken: BROWSER_REFRESH_TOKEN, expiration: FUTURE },
    {
      _id: 'session-2',
      user: USER_ID,
      refreshToken: OTHER_BROWSER_REFRESH_TOKEN,
      expiration: FUTURE,
    },
    { _id: 'session-3', user: 'user-2', refreshToken: 'user-2-refresh-token', expiration: FUTURE },
  ];

  const deps = {
    getUserById: jest.fn(async () => ({ ...doc })),
    updateTwoFactorEnrollment: jest.fn(
      async (
        _userId: string,
        guard: Partial<StoredTwoFactorAccount>,
        update: Partial<StoredTwoFactorAccount>,
      ) => {
        const matches = (Object.keys(guard) as (keyof StoredTwoFactorAccount)[]).every(
          (key) => JSON.stringify(doc[key] ?? null) === JSON.stringify(guard[key] ?? null),
        );
        if (doc.twoFactorEnabled || !matches) {
          return null;
        }
        doc = { ...doc, ...update };
        return { ...doc };
      },
    ),
    findSession: jest.fn(async (query: { userId: string; refreshToken: string }) => {
      const session = sessions.find(
        (candidate) =>
          candidate.user === query.userId && candidate.refreshToken === query.refreshToken,
      );
      return session ?? null;
    }),
    deleteSession: jest.fn(async ({ sessionId }: { sessionId: string }) => {
      const index = sessions.findIndex((candidate) => candidate._id === sessionId);
      if (index >= 0) {
        sessions.splice(index, 1);
      }
      return { deletedCount: index >= 0 ? 1 : 0 };
    }),
    clearCloudFrontCookies: jest.fn(),
    deleteAllUserSessions: jest.fn(async () => ({ deletedCount: 0 })),
    updateUser: jest.fn(),
    awaitAuthUserDocEviction: jest.fn(async () => undefined),
    setAuthTokens: jest.fn(async () => 'auth-token'),
    getTOTPSecret: jest.fn(),
    verifyTOTP: jest.fn(),
    verifyBackupCode: jest.fn(),
    generateBackupCodes: jest.fn(),
  };

  const { cancel2FASetup } = createEnrollmentControllers(
    deps as unknown as EnrollmentControllerDependencies,
  );

  const run = async (
    request: {
      user?: { id: string };
      cookies?: Record<string, string>;
      twoFactorSetupExpired?: boolean;
    } = {
      user: { id: USER_ID },
      cookies: { refreshToken: BROWSER_REFRESH_TOKEN },
    },
  ) => {
    const res = createResponse();
    await cancel2FASetup(
      { body: {}, ...request } as unknown as Parameters<typeof cancel2FASetup>[0],
      res,
    );
    return res;
  };

  return { deps, run, sessions, getDoc: () => doc };
}

describe('cancel2FASetup', () => {
  it('discards the staged secret, the staged codes and every outstanding nonce', async () => {
    const { run, getDoc } = createHarness();

    const res = await run();

    expect(res.status).toHaveBeenCalledWith(200);
    expect(getDoc()).toMatchObject({
      twoFactorEnabled: false,
      pendingTotpSecret: null,
      pendingBackupCodes: [],
      twoFactorAcknowledgementNonceHash: null,
      twoFactorFinalizationNonceHash: null,
    });
  });

  it('writes only against the secret it observed, so a concurrent promotion is never undone', async () => {
    const { run, deps } = createHarness();

    await run();

    expect(deps.updateTwoFactorEnrollment).toHaveBeenCalledWith(
      USER_ID,
      { pendingTotpSecret: 'encrypted-secret' },
      {
        pendingTotpSecret: null,
        pendingBackupCodes: [],
        twoFactorAcknowledgementNonceHash: null,
        twoFactorFinalizationNonceHash: null,
      },
    );
  });

  it('leaves a promoted enrollment and its factors untouched', async () => {
    const { run, deps, getDoc } = createHarness({
      twoFactorEnabled: true,
      totpSecret: 'live-secret',
      pendingTotpSecret: undefined,
      pendingBackupCodes: [],
      twoFactorAcknowledgementNonceHash: null,
      twoFactorFinalizationNonceHash: null,
    });

    const res = await run();

    expect(res.status).toHaveBeenCalledWith(200);
    expect(deps.updateTwoFactorEnrollment).not.toHaveBeenCalled();
    expect(getDoc()).toMatchObject({ twoFactorEnabled: true, totpSecret: 'live-secret' });
  });

  it('skips the write when nothing is staged but still ends the session', async () => {
    const { run, deps, sessions } = createHarness({
      pendingTotpSecret: undefined,
      pendingBackupCodes: [],
      twoFactorAcknowledgementNonceHash: null,
      twoFactorFinalizationNonceHash: null,
    });

    const res = await run();

    expect(res.status).toHaveBeenCalledWith(200);
    expect(deps.updateTwoFactorEnrollment).not.toHaveBeenCalled();
    expect(sessions.map((session) => session._id)).not.toContain('session-1');
  });

  it('ends the session this browser presents and no other', async () => {
    const { run, deps, sessions } = createHarness();

    await run();

    expect(deps.findSession).toHaveBeenCalledWith(
      { userId: USER_ID, refreshToken: BROWSER_REFRESH_TOKEN },
      { lean: false },
    );
    expect(deps.deleteSession).toHaveBeenCalledTimes(1);
    expect(deps.deleteSession).toHaveBeenCalledWith({ sessionId: 'session-1' });
    expect(deps.deleteAllUserSessions).not.toHaveBeenCalled();
    expect(sessions.map((session) => session._id)).toEqual(['session-2', 'session-3']);
  });

  it('never deletes a session that belongs to a different account', async () => {
    const { run, deps, sessions } = createHarness();

    const res = await run({
      user: { id: USER_ID },
      cookies: { refreshToken: 'user-2-refresh-token' },
    });

    expect(res.status).toHaveBeenCalledWith(200);
    expect(deps.deleteSession).not.toHaveBeenCalled();
    expect(sessions.map((session) => session._id)).toContain('session-3');
  });

  it('clears the credentials the browser holds, including the CDN cookies', async () => {
    const { run, deps } = createHarness();

    const res = await run();

    expect(res.clearCookie).toHaveBeenCalledWith('refreshToken');
    expect(res.clearCookie).toHaveBeenCalledWith('token_provider');
    expect(res.clearCookie).toHaveBeenCalledWith('session_hint');
    expect(deps.clearCloudFrontCookies).toHaveBeenCalledWith(res, {
      userId: USER_ID,
      tenantId: 'tenant-a',
      storageRegion: 'eu-central-1',
    });
  });

  it('signs out a browser that presents no refresh cookie', async () => {
    const { run, deps, sessions } = createHarness();

    const res = await run({ user: { id: USER_ID } });

    expect(res.status).toHaveBeenCalledWith(200);
    expect(deps.findSession).not.toHaveBeenCalled();
    expect(deps.deleteSession).not.toHaveBeenCalled();
    expect(sessions).toHaveLength(3);
    expect(res.clearCookie).toHaveBeenCalledWith('refreshToken');
  });

  it('can be repeated without error', async () => {
    const { run } = createHarness();

    await run();
    const second = await run();

    expect(second.status).toHaveBeenCalledWith(200);
  });

  it('rejects a request without a validated setup user and changes nothing', async () => {
    const { run, deps, sessions } = createHarness();

    const res = await run({ cookies: { refreshToken: BROWSER_REFRESH_TOKEN } });

    expect(res.status).toHaveBeenCalledWith(401);
    expect(deps.updateTwoFactorEnrollment).not.toHaveBeenCalled();
    expect(deps.deleteSession).not.toHaveBeenCalled();
    expect(res.clearCookie).not.toHaveBeenCalled();
    expect(sessions).toHaveLength(3);
  });

  describe('with a setup token that expired while the user was on the screen', () => {
    const expired = {
      user: { id: USER_ID },
      cookies: { refreshToken: BROWSER_REFRESH_TOKEN },
      twoFactorSetupExpired: true,
    };

    it('ends the presented session and clears the browser', async () => {
      const { run, deps, sessions } = createHarness();

      const res = await run(expired);

      expect(res.status).toHaveBeenCalledWith(200);
      expect(res.clearCookie).toHaveBeenCalledWith('refreshToken');
      expect(deps.deleteSession).toHaveBeenCalledWith({ sessionId: 'session-1' });
      expect(sessions.map((session) => session._id)).toEqual(['session-2', 'session-3']);
    });

    /** An old token that leaked must not be able to wipe an enrollment someone is in the middle of. */
    it('leaves the staged enrollment alone', async () => {
      const { run, deps, getDoc } = createHarness();

      await run(expired);

      expect(deps.updateTwoFactorEnrollment).not.toHaveBeenCalled();
      expect(getDoc()).toMatchObject({
        pendingTotpSecret: 'encrypted-secret',
        pendingBackupCodes: [{ codeHash: 'staged-hash', used: false }],
        twoFactorAcknowledgementNonceHash: 'ack-hash',
        twoFactorFinalizationNonceHash: 'finalization-hash',
      });
    });
  });

  describe('when a write fails', () => {
    /** The cookies are cleared before any fallible write, so a 500 cannot leave the credential in the browser. */
    it('still clears the browser and the staged enrollment when the session cannot be deleted', async () => {
      const { run, deps, getDoc } = createHarness();
      deps.deleteSession.mockRejectedValueOnce(new Error('connection string leaked here'));

      const res = await run();

      expect(res.status).toHaveBeenCalledWith(500);
      expect(res.json).toHaveBeenCalledWith({ message: 'Something went wrong' });
      expect(res.clearCookie).toHaveBeenCalledWith('refreshToken');
      expect(getDoc().pendingTotpSecret).toBeNull();
    });

    it('still deletes the session when the staged enrollment cannot be cleared', async () => {
      const { run, deps, sessions } = createHarness();
      deps.updateTwoFactorEnrollment.mockRejectedValueOnce(new Error('write failed'));

      const res = await run();

      expect(res.status).toHaveBeenCalledWith(500);
      expect(res.json).toHaveBeenCalledWith({ message: 'Something went wrong' });
      expect(sessions.map((session) => session._id)).not.toContain('session-1');
    });

    it('reports a failure without touching the browser when the account cannot be read', async () => {
      const { run, deps } = createHarness();
      deps.getUserById.mockRejectedValueOnce(new Error('database unavailable'));

      const res = await run();

      expect(res.status).toHaveBeenCalledWith(500);
      expect(res.json).toHaveBeenCalledWith({ message: 'Something went wrong' });
      expect(deps.deleteSession).not.toHaveBeenCalled();
    });
  });
});

const ORIGINAL_JWT_SECRET = process.env.JWT_SECRET;
const ORIGINAL_ENFORCE_2FA = process.env.ENFORCE_TWO_FACTOR_AUTHENTICATION;

function mockResponse() {
  const res: { status: jest.Mock; json: jest.Mock } = {
    status: jest.fn(),
    json: jest.fn(),
  };
  res.status.mockReturnValue(res);
  res.json.mockReturnValue(res);
  return res as unknown as import('express').Response;
}

function makeUser(overrides: Partial<StoredTwoFactorAccount> = {}): StoredTwoFactorAccount {
  return {
    _id: 'user-1',
    provider: 'local',
    twoFactorEnabled: false,
    ...overrides,
  } as unknown as StoredTwoFactorAccount;
}

function makeDeps(
  overrides: Partial<EnrollmentControllerDependencies> = {},
): EnrollmentControllerDependencies {
  return {
    updateUser: jest.fn().mockResolvedValue(null),
    awaitAuthUserDocEviction: jest.fn().mockResolvedValue(undefined),
    getUserById: jest.fn().mockResolvedValue(null),
    getTOTPSecret: jest.fn().mockResolvedValue(null),
    verifyTOTP: jest.fn().mockResolvedValue(false),
    verifyBackupCode: jest.fn().mockResolvedValue(false),
    generateBackupCodes: jest.fn().mockResolvedValue({ plainCodes: [], codeObjects: [] }),
    updateTwoFactorEnrollment: jest.fn().mockResolvedValue(null),
    findSession: jest.fn().mockResolvedValue(null),
    deleteSession: jest.fn().mockResolvedValue({}),
    deleteAllUserSessions: jest.fn().mockResolvedValue({}),
    clearCloudFrontCookies: jest.fn(),
    setAuthTokens: jest.fn().mockResolvedValue('jwt-token'),
    ...overrides,
  };
}

describe('createEnrollmentControllers authMethod', () => {
  beforeEach(() => {
    process.env.JWT_SECRET = 'test-secret';
    delete process.env.ENFORCE_TWO_FACTOR_AUTHENTICATION;
  });

  afterAll(() => {
    if (ORIGINAL_JWT_SECRET === undefined) {
      delete process.env.JWT_SECRET;
    } else {
      process.env.JWT_SECRET = ORIGINAL_JWT_SECRET;
    }
    if (ORIGINAL_ENFORCE_2FA === undefined) {
      delete process.env.ENFORCE_TWO_FACTOR_AUTHENTICATION;
    } else {
      process.env.ENFORCE_TWO_FACTOR_AUTHENTICATION = ORIGINAL_ENFORCE_2FA;
    }
  });

  it('marks a password + TOTP login as authMethod local, not blank', async () => {
    const user = makeUser({ twoFactorEnabled: true, totpSecret: 'encrypted-secret' });
    const tempToken = generateTwoFactorLoginChallengeToken('user-1', process.env.JWT_SECRET!);
    const setAuthTokens = jest.fn().mockResolvedValue('jwt-token');
    const deps = makeDeps({
      getUserById: jest.fn().mockResolvedValue(user),
      getTOTPSecret: jest.fn().mockResolvedValue('plain-secret'),
      verifyTOTP: jest.fn().mockResolvedValue(true),
      setAuthTokens,
    });
    const { verify2FAWithTempToken } = createEnrollmentControllers(deps);
    const req = { body: { tempToken, token: '123456' } } as unknown as Parameters<
      typeof verify2FAWithTempToken
    >[0];
    const res = mockResponse();

    await verify2FAWithTempToken(req, res);

    expect(setAuthTokens).toHaveBeenCalledWith(
      user._id,
      res,
      null,
      req,
      expect.objectContaining({ authMethod: 'local' }),
    );
  });

  it('marks a fresh 2FA-setup promotion as authMethod local, not blank', async () => {
    process.env.ENFORCE_TWO_FACTOR_AUTHENTICATION = 'true';
    const promotedUser = makeUser({ twoFactorEnabled: true });
    const pendingUser = makeUser({
      twoFactorEnabled: false,
      pendingTotpSecret: 'pending-secret',
      pendingBackupCodes: [{ codeHash: 'hash', used: false }],
    });
    const setAuthTokens = jest.fn().mockResolvedValue('jwt-token');
    const deps = makeDeps({
      getUserById: jest.fn().mockResolvedValue(pendingUser),
      updateTwoFactorEnrollment: jest.fn().mockResolvedValue(promotedUser),
      setAuthTokens,
    });
    const { finalize2FASetup } = createEnrollmentControllers(deps);
    const req = {
      user: { id: 'user-1' },
      twoFactorEnrollmentNonce: 'finalization-nonce',
    } as unknown as Parameters<typeof finalize2FASetup>[0];
    const res = mockResponse();

    await finalize2FASetup(req, res);

    expect(setAuthTokens).toHaveBeenCalledWith(
      promotedUser._id,
      res,
      null,
      req,
      expect.objectContaining({ authMethod: 'local' }),
    );
  });

  it('records ldap as the auth method when an LDAP login completes a TOTP challenge', async () => {
    const user = makeUser({ twoFactorEnabled: true, totpSecret: 'encrypted-secret' });
    const tempToken = generateTwoFactorLoginChallengeToken(
      'user-1',
      process.env.JWT_SECRET!,
      'ldap',
    );
    const setAuthTokens = jest.fn().mockResolvedValue('jwt-token');
    const deps = makeDeps({
      getUserById: jest.fn().mockResolvedValue(user),
      getTOTPSecret: jest.fn().mockResolvedValue('plain-secret'),
      verifyTOTP: jest.fn().mockResolvedValue(true),
      setAuthTokens,
    });
    const { verify2FAWithTempToken } = createEnrollmentControllers(deps);
    const req = { body: { tempToken, token: '123456' } } as unknown as Parameters<
      typeof verify2FAWithTempToken
    >[0];
    const res = mockResponse();

    await verify2FAWithTempToken(req, res);

    expect(setAuthTokens).toHaveBeenCalledWith(
      user._id,
      res,
      null,
      req,
      expect.objectContaining({ authMethod: 'ldap' }),
    );
  });

  it('records passkey as the auth method when a passkey login completes a TOTP challenge', async () => {
    const user = makeUser({ twoFactorEnabled: true, totpSecret: 'encrypted-secret' });
    const tempToken = generateTwoFactorLoginChallengeToken(
      'user-1',
      process.env.JWT_SECRET!,
      'passkey',
    );
    const setAuthTokens = jest.fn().mockResolvedValue('jwt-token');
    const deps = makeDeps({
      getUserById: jest.fn().mockResolvedValue(user),
      getTOTPSecret: jest.fn().mockResolvedValue('plain-secret'),
      verifyTOTP: jest.fn().mockResolvedValue(true),
      setAuthTokens,
    });
    const { verify2FAWithTempToken } = createEnrollmentControllers(deps);
    const req = { body: { tempToken, token: '123456' } } as unknown as Parameters<
      typeof verify2FAWithTempToken
    >[0];
    const res = mockResponse();

    await verify2FAWithTempToken(req, res);

    expect(setAuthTokens).toHaveBeenCalledWith(
      user._id,
      res,
      null,
      req,
      expect.objectContaining({ authMethod: 'passkey' }),
    );
  });

  it('falls back to local when the login challenge carries an invalid method', async () => {
    const user = makeUser({ twoFactorEnabled: true, totpSecret: 'encrypted-secret' });
    const forgedToken = jwt.sign(
      {
        userId: 'user-1',
        purpose: TWO_FACTOR_TOKEN_PURPOSE.LOGIN_CHALLENGE,
        issuedAtMs: Date.now(),
        authMethod: 'not-a-real-method',
      },
      process.env.JWT_SECRET!,
      { expiresIn: '5m' },
    );
    const setAuthTokens = jest.fn().mockResolvedValue('jwt-token');
    const deps = makeDeps({
      getUserById: jest.fn().mockResolvedValue(user),
      getTOTPSecret: jest.fn().mockResolvedValue('plain-secret'),
      verifyTOTP: jest.fn().mockResolvedValue(true),
      setAuthTokens,
    });
    const { verify2FAWithTempToken } = createEnrollmentControllers(deps);
    const req = { body: { tempToken: forgedToken, token: '123456' } } as unknown as Parameters<
      typeof verify2FAWithTempToken
    >[0];
    const res = mockResponse();

    await verify2FAWithTempToken(req, res);

    expect(setAuthTokens).toHaveBeenCalledWith(
      user._id,
      res,
      null,
      req,
      expect.objectContaining({ authMethod: 'local' }),
    );
  });

  /**
   * The login method travels through three tokens, not one: the setup token the login controller
   * mints, the acknowledgement token `confirm2FASetupWithTempToken` mints in its place, and the
   * finalization token `acknowledge2FASetup` mints in turn. Only the last of those reaches the
   * session `finalize2FASetup` mints, so this exercises the real middleware alongside the
   * controllers rather than stamping the claim directly onto a request.
   */
  it('preserves the login method across the required-enrollment continuation', async () => {
    process.env.ENFORCE_TWO_FACTOR_AUTHENTICATION = 'true';
    const pendingUser = makeUser({
      twoFactorEnabled: false,
      pendingTotpSecret: 'pending-secret',
      pendingBackupCodes: [{ codeHash: 'hash', used: false }],
    });
    const promotedUser = makeUser({ twoFactorEnabled: true });
    const setAuthTokens = jest.fn().mockResolvedValue('jwt-token');
    const deps = makeDeps({
      getUserById: jest.fn().mockResolvedValue(pendingUser),
      getTOTPSecret: jest.fn().mockResolvedValue('plain-secret'),
      verifyTOTP: jest.fn().mockResolvedValue(true),
      generateBackupCodes: jest.fn().mockResolvedValue({
        plainCodes: ['backup-code'],
        codeObjects: [{ codeHash: 'hash', used: false }],
      }),
      updateTwoFactorEnrollment: jest.fn().mockResolvedValue(promotedUser),
      setAuthTokens,
    });
    const { confirm2FASetupWithTempToken, acknowledge2FASetup, finalize2FASetup } =
      createEnrollmentControllers(deps);

    const setupToken = generateTwoFactorSetupToken('user-1', process.env.JWT_SECRET!, 'ldap');
    const confirmReq = { body: { tempToken: setupToken, token: '123456' } } as unknown as Request;
    requireTwoFactorSetupToken(confirmReq, mockResponse(), jest.fn());
    const confirmRes = mockResponse();
    await confirm2FASetupWithTempToken(
      confirmReq as unknown as Parameters<typeof confirm2FASetupWithTempToken>[0],
      confirmRes,
    );
    const acknowledgementToken = (confirmRes.json as jest.Mock).mock.calls[0][0]
      .acknowledgementToken;

    const ackReq = { body: { acknowledgementToken } } as unknown as Request;
    requireTwoFactorSetupAcknowledgementToken(ackReq, mockResponse(), jest.fn());
    const ackRes = mockResponse();
    await acknowledge2FASetup(
      ackReq as unknown as Parameters<typeof acknowledge2FASetup>[0],
      ackRes,
    );
    const finalizationToken = (ackRes.json as jest.Mock).mock.calls[0][0].finalizationToken;

    const finalizeReq = { body: { finalizationToken } } as unknown as Request;
    requireTwoFactorSetupFinalizationToken(finalizeReq, mockResponse(), jest.fn());
    const finalizeRes = mockResponse();
    await finalize2FASetup(
      finalizeReq as unknown as Parameters<typeof finalize2FASetup>[0],
      finalizeRes,
    );

    expect(setAuthTokens).toHaveBeenCalledWith(
      promotedUser._id,
      finalizeRes,
      null,
      finalizeReq,
      expect.objectContaining({ authMethod: 'ldap' }),
    );
  });
});

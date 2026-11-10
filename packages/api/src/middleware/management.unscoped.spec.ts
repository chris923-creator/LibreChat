import jwt from 'jsonwebtoken';
import mongoose from 'mongoose';
import { createServer } from 'http';
import { generateKeyPairSync } from 'crypto';
import { configSchema } from 'librechat-data-provider';
import { MongoMemoryServer } from 'mongodb-memory-server';
import { PermissionBits, PrincipalType, ResourceType } from 'librechat-data-provider';
import {
  createMethods,
  createModels,
  getTenantId,
  resetTenantStrictCache,
  SystemCapabilities,
  tenantStorage,
} from '@librechat/data-schemas';
import type { AllMethods, AppConfig, IUser } from '@librechat/data-schemas';
import type { Server, ServerResponse } from 'http';
import type { Request, Response } from 'express';
import type { JwtPayload } from 'jsonwebtoken';
import type { AddressInfo } from 'net';
import type { AgentManagementReadDeps } from '../agents/reads';
import { ConfigReloadError, createCustomConfigLoader } from '../app/loader';
import { createAgentManagementReadHandlers } from '../agents/reads';
import { clearOidcAccessTokenCache } from '../auth/oidc';
import { createAgentManagementAuth } from './management';

const AUDIENCE = 'https://agents.example.com';
const KEY_ID = 'synthetic-management-key';
const TENANT_A = 'tenant-a';
const TENANT_B = 'tenant-b';
const UNSCOPED_CLIENT = 'unscoped-client';
const TENANT_CLIENT = 'tenant-client';
const CROSS_CLIENT = 'cross-tenant-client';
const UNSCOPED_ON_TENANT_USER = 'unscoped-on-tenant-user';
const TENANT_ON_UNSCOPED_USER = 'tenant-on-unscoped-user';
const DISABLED_CLIENT = 'disabled-client';

const keyPair = generateKeyPairSync('rsa', { modulusLength: 2048 });
const publicJwk = {
  ...keyPair.publicKey.export({ format: 'jwk' }),
  alg: 'RS256',
  kid: KEY_ID,
  use: 'sig',
};

let issuer = '';
let server: Server;
let mongoServer: MongoMemoryServer;
let methods: AllMethods;
let originalStrictMode: string | undefined;
let unscopedUserId = '';
let tenantUserId = '';

function sendJson(res: ServerResponse, body: unknown): void {
  res.writeHead(200, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(body));
}

function signToken(overrides: JwtPayload = {}): string {
  const now = Math.floor(Date.now() / 1000);
  return jwt.sign(
    {
      iss: issuer,
      aud: AUDIENCE,
      sub: `${UNSCOPED_CLIENT}@clients`,
      azp: UNSCOPED_CLIENT,
      iat: now,
      exp: now + 300,
      ...overrides,
    },
    keyPair.privateKey,
    { algorithm: 'RS256', keyid: KEY_ID },
  );
}

function managementDocument(clients: Array<Record<string, unknown>>, oidcIssuer = issuer) {
  return {
    version: '1.3.17',
    endpoints: {
      agents: {
        managementApi: {
          auth: {
            oidc: {
              enabled: true,
              issuer: oidcIssuer,
              audience: AUDIENCE,
            },
            clients,
          },
        },
      },
    },
  };
}

function parseManagementConfig(clients: Array<Record<string, unknown>>): AppConfig {
  const result = configSchema.strict().safeParse(managementDocument(clients));
  if (!result.success) {
    throw new Error(`management config rejected: ${JSON.stringify(result.error.issues)}`);
  }
  return result.data as unknown as AppConfig;
}

async function loadThroughStrictLoader(config: unknown) {
  const loader = createCustomConfigLoader({
    defaultConfigPath: 'librechat.yaml',
    loadLocal: () => config,
    redactConfig: (value) => value,
  });
  const previous = process.env.CONFIG_PATH;
  process.env.CONFIG_PATH = 'librechat.yaml';
  try {
    return await loader(false, { mode: 'reload' });
  } finally {
    if (previous == null) {
      delete process.env.CONFIG_PATH;
    } else {
      process.env.CONFIG_PATH = previous;
    }
  }
}

function createResponse(): Response & { statusCode?: number; body?: unknown } {
  const res = {
    statusCode: 200,
    body: undefined as unknown,
    status(code: number) {
      this.statusCode = code;
      return this;
    },
    json(body: unknown) {
      this.body = body;
      return this;
    },
  };
  return res as unknown as Response & { statusCode?: number; body?: unknown };
}

function createRequest(token: string, params: Record<string, string> = {}): Request {
  return {
    headers: { authorization: `Bearer ${token}` },
    query: {},
    params,
  } as Request;
}

beforeAll(async () => {
  originalStrictMode = process.env.TENANT_ISOLATION_STRICT;
  delete process.env.TENANT_ISOLATION_STRICT;
  resetTenantStrictCache();

  server = createServer((req, res) => {
    if (req.url === '/.well-known/openid-configuration') {
      sendJson(res, { issuer, jwks_uri: `${issuer}/.well-known/jwks.json` });
      return;
    }
    if (req.url === '/.well-known/jwks.json') {
      sendJson(res, { keys: [publicJwk] });
      return;
    }
    res.writeHead(404).end();
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  issuer = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;

  mongoServer = await MongoMemoryServer.create();
  await mongoose.connect(mongoServer.getUri());
  createModels(mongoose);
  methods = createMethods(mongoose);
  const User = mongoose.models.User as mongoose.Model<IUser>;
  const Agent = mongoose.models.Agent;
  const SystemGrant = mongoose.models.SystemGrant;

  const unscopedUser = await User.create({
    email: 'service@example.com',
    name: 'Service',
    username: 'service',
    provider: 'local',
    role: 'USER',
  });
  const tenantUser = await tenantStorage.run({ tenantId: TENANT_A }, () =>
    User.create({
      email: 'tenant-a@example.com',
      name: 'Tenant A',
      username: 'tenant-a',
      provider: 'local',
      role: 'USER',
      tenantId: TENANT_A,
    }),
  );
  unscopedUserId = unscopedUser._id.toString();
  tenantUserId = tenantUser._id.toString();

  const legacyEditable = await Agent.create({
    id: 'agent_legacy_edit',
    name: 'Legacy editable',
    instructions: 'legacy-edit-instructions',
    provider: 'openai',
    model: 'gpt-4',
    author: unscopedUser._id,
  });
  const legacyView = await Agent.create({
    id: 'agent_legacy_view',
    name: 'Legacy view',
    instructions: 'legacy-view-instructions',
    provider: 'openai',
    model: 'gpt-4',
    author: unscopedUser._id,
  });
  await Agent.create({
    id: 'agent_legacy_hidden',
    name: 'Legacy hidden',
    instructions: 'legacy-hidden-instructions',
    provider: 'openai',
    model: 'gpt-4',
    author: unscopedUser._id,
  });
  const legacyShared = await Agent.create({
    id: 'agent_shared',
    name: 'Shared legacy',
    instructions: 'legacy-shared-instructions',
    provider: 'openai',
    model: 'gpt-4',
    author: unscopedUser._id,
  });
  const tenantEditable = await tenantStorage.run({ tenantId: TENANT_A }, () =>
    Agent.create({
      id: 'agent_tenant_edit',
      name: 'Tenant editable',
      instructions: 'tenant-edit-instructions',
      provider: 'openai',
      model: 'gpt-4',
      author: tenantUser._id,
      tenantId: TENANT_A,
    }),
  );
  await tenantStorage.run({ tenantId: TENANT_A }, () =>
    Agent.create({
      id: 'agent_shared',
      name: 'Shared tenant',
      instructions: 'tenant-shared-instructions',
      provider: 'openai',
      model: 'gpt-4',
      author: tenantUser._id,
      tenantId: TENANT_A,
    }),
  );

  await methods.grantPermission(
    PrincipalType.USER,
    unscopedUser._id,
    ResourceType.AGENT,
    legacyEditable._id,
    PermissionBits.VIEW | PermissionBits.EDIT,
    unscopedUser._id,
  );
  await methods.grantPermission(
    PrincipalType.USER,
    unscopedUser._id,
    ResourceType.AGENT,
    legacyView._id,
    PermissionBits.VIEW,
    unscopedUser._id,
  );
  await methods.grantPermission(
    PrincipalType.USER,
    unscopedUser._id,
    ResourceType.AGENT,
    legacyShared._id,
    PermissionBits.VIEW | PermissionBits.EDIT,
    unscopedUser._id,
  );
  await tenantStorage.run({ tenantId: TENANT_A }, () =>
    methods.grantPermission(
      PrincipalType.USER,
      tenantUser._id,
      ResourceType.AGENT,
      tenantEditable._id,
      PermissionBits.VIEW | PermissionBits.EDIT,
      tenantUser._id,
    ),
  );
  await tenantStorage.run({ tenantId: TENANT_A }, () =>
    SystemGrant.create({
      principalType: PrincipalType.USER,
      principalId: unscopedUser._id,
      capability: SystemCapabilities.MANAGE_AGENTS,
      tenantId: TENANT_A,
    }),
  );
}, 60000);

afterEach(() => {
  clearOidcAccessTokenCache();
});

afterAll(async () => {
  if (originalStrictMode == null) {
    delete process.env.TENANT_ISOLATION_STRICT;
  } else {
    process.env.TENANT_ISOLATION_STRICT = originalStrictMode;
  }
  resetTenantStrictCache();
  await mongoose.disconnect();
  await mongoServer.stop();
  await new Promise<void>((resolve, reject) =>
    server.close((error) => (error ? reject(error) : resolve())),
  );
});

function clients(): Array<Record<string, unknown>> {
  return [
    { clientId: UNSCOPED_CLIENT, userId: unscopedUserId },
    { clientId: TENANT_CLIENT, userId: tenantUserId, tenantId: TENANT_A },
    { clientId: CROSS_CLIENT, userId: tenantUserId, tenantId: TENANT_B },
    { clientId: UNSCOPED_ON_TENANT_USER, userId: tenantUserId },
    { clientId: TENANT_ON_UNSCOPED_USER, userId: unscopedUserId, tenantId: TENANT_A },
    { clientId: DISABLED_CLIENT, userId: unscopedUserId, enabled: false },
  ];
}

function createAuth() {
  return createAgentManagementAuth({
    findUser: methods.findUser,
    isPrincipalActive: methods.isAgentTriggerPrincipalActive,
    getAppConfig: async () => parseManagementConfig(clients()),
  });
}

function withAgentId(req: Request, id: string): Request {
  req.params = { id };
  return req;
}

function createHandlers() {
  return createAgentManagementReadHandlers({
    getRoleByName: methods.getRoleByName,
    getAgentWithVersionCount:
      methods.getAgentWithVersionCount as AgentManagementReadDeps['getAgentWithVersionCount'],
    getAgentManagementListByAccess:
      methods.getAgentManagementListByAccess as AgentManagementReadDeps['getAgentManagementListByAccess'],
    findAccessibleResources: async ({
      userId,
      role,
      idOnTheSource,
      resourceType,
      requiredPermissions,
    }) => {
      const principals = await methods.getUserPrincipals({
        userId,
        role,
        idOnTheSource: idOnTheSource ?? null,
      });
      return methods.findAccessibleResources(principals, resourceType, requiredPermissions);
    },
    checkPermission: async ({ userId, role, resourceType, resourceId, requiredPermission }) => {
      const principals = await methods.getUserPrincipals({
        userId,
        role,
        idOnTheSource: null,
      });
      return methods.hasPermission(principals, resourceType, resourceId, requiredPermission);
    },
    hasCapability: async (user, capability) => {
      const principals = await methods.getUserPrincipals({
        userId: user.id,
        role: user.role,
        idOnTheSource: user.idOnTheSource ?? null,
      });
      return methods.hasCapabilityForPrincipals({
        principals,
        capability,
        tenantId:
          typeof user.tenantId === 'string' && user.tenantId !== '' ? user.tenantId : undefined,
      });
    },
  });
}

async function authenticate(token: string) {
  const req = createRequest(token);
  const res = createResponse();
  let downstreamTenant: string | undefined;
  let continued = false;
  await createAuth()(req, res, () => {
    continued = true;
    downstreamTenant = getTenantId();
  });
  return { req, res, continued, downstreamTenant };
}

describe('strict management config loader', () => {
  it('accepts an unscoped client through the strict loader', async () => {
    const loaded = await loadThroughStrictLoader(
      managementDocument(
        [{ clientId: 'machine-client', userId: '507f1f77bcf86cd799439011' }],
        'https://issuer.example.com',
      ),
    );

    expect(loaded?.endpoints?.agents?.managementApi?.auth?.clients).toEqual([
      { clientId: 'machine-client', userId: '507f1f77bcf86cd799439011' },
    ]);
  });

  it.each([
    [
      'an empty tenant',
      { clientId: 'machine-client', userId: '507f1f77bcf86cd799439011', tenantId: '' },
    ],
    [
      'the system tenant',
      { clientId: 'machine-client', userId: '507f1f77bcf86cd799439011', tenantId: '__SYSTEM__' },
    ],
    [
      'a role field',
      { clientId: 'machine-client', userId: '507f1f77bcf86cd799439011', role: 'ADMIN' },
    ],
    ['a missing user', { clientId: 'machine-client' }],
  ])('rejects %s', async (_label, client) => {
    await expect(
      loadThroughStrictLoader(managementDocument([client], 'https://issuer.example.com')),
    ).rejects.toBeInstanceOf(ConfigReloadError);
  });
});

describe('unscoped management authentication and agent reads', () => {
  it('authenticates a dedicated unscoped USER and lists only that user EDIT grants', async () => {
    const { req, res, continued, downstreamTenant } = await authenticate(signToken());
    const listResponse = createResponse();

    expect(continued).toBe(true);
    expect(res.statusCode).toBe(200);
    expect(downstreamTenant).toBeUndefined();
    expect(req.user).toMatchObject({ id: unscopedUserId, role: 'USER' });
    expect((req.user as IUser | undefined)?.tenantId).toBeUndefined();

    const handlers = createHandlers();
    const foreignResponse = createResponse();
    await handlers.list(req, listResponse);
    await handlers.get(withAgentId(req, 'agent_tenant_edit'), foreignResponse);

    const body = listResponse.body as {
      data: Array<{ id: string; instructions?: string; tenantId?: string }>;
    };
    expect(listResponse.statusCode).toBe(200);
    expect(body.data.map((agent) => agent.id).sort()).toEqual([
      'agent_legacy_edit',
      'agent_shared',
    ]);
    expect(body.data.map((agent) => agent.instructions).sort()).toEqual([
      'legacy-edit-instructions',
      'legacy-shared-instructions',
    ]);
    expect(body.data.every((agent) => agent.tenantId == null)).toBe(true);
    expect(JSON.stringify(body)).not.toContain('legacy-view-instructions');
    expect(JSON.stringify(body)).not.toContain('legacy-hidden-instructions');
    expect(JSON.stringify(body)).not.toContain('tenant-edit-instructions');
    expect(foreignResponse.statusCode).toBe(404);
    expect(JSON.stringify(foreignResponse.body)).not.toContain('tenant-edit-instructions');
  });

  it('keeps VIEW from satisfying the management detail EDIT check', async () => {
    const { req } = await authenticate(signToken());
    const viewResponse = createResponse();
    const hiddenResponse = createResponse();
    const handlers = createHandlers();

    await handlers.get(withAgentId(req, 'agent_legacy_view'), viewResponse);
    await handlers.get(withAgentId(req, 'agent_legacy_hidden'), hiddenResponse);

    expect(viewResponse.statusCode).toBe(403);
    expect(viewResponse.body).toEqual({
      error: { code: 'permission_denied', message: 'Permission denied' },
    });
    expect(hiddenResponse.statusCode).toBe(403);
    expect(JSON.stringify(viewResponse.body)).not.toContain('legacy-view-instructions');
    expect(JSON.stringify(hiddenResponse.body)).not.toContain('legacy-hidden-instructions');
  });

  it('returns the unscoped copy when a public id also exists in a tenant', async () => {
    const { req } = await authenticate(signToken());
    const response = createResponse();

    await createHandlers().get(withAgentId(req, 'agent_shared'), response);

    expect(response.statusCode).toBe(200);
    expect((response.body as { instructions?: string; tenantId?: string }).instructions).toBe(
      'legacy-shared-instructions',
    );
    expect(response.body).not.toHaveProperty('tenantId');
    expect(JSON.stringify(response.body)).not.toContain('tenant-shared-instructions');
  });

  it('keeps an exact tenant binding on that tenant only', async () => {
    const { req, continued, downstreamTenant } = await authenticate(
      signToken({ azp: TENANT_CLIENT, sub: `${TENANT_CLIENT}@clients` }),
    );
    const listResponse = createResponse();
    const foreignResponse = createResponse();
    const handlers = createHandlers();

    expect(continued).toBe(true);
    expect(downstreamTenant).toBe(TENANT_A);
    expect(req.user).toMatchObject({ id: tenantUserId, role: 'USER', tenantId: TENANT_A });

    await handlers.list(req, listResponse);
    await handlers.get(withAgentId(req, 'agent_legacy_edit'), foreignResponse);

    const body = listResponse.body as { data: Array<{ id: string; instructions?: string }> };
    expect(body.data.map((agent) => agent.id)).toEqual(['agent_tenant_edit']);
    expect(body.data[0]?.instructions).toBe('tenant-edit-instructions');
    expect(foreignResponse.statusCode).toBe(404);
    expect(JSON.stringify(listResponse.body)).not.toContain('legacy-edit-instructions');
  });

  it.each([
    ['a cross-tenant binding', { azp: CROSS_CLIENT, sub: `${CROSS_CLIENT}@clients` }],
    [
      'an unscoped binding for a tenant user',
      { azp: UNSCOPED_ON_TENANT_USER, sub: `${UNSCOPED_ON_TENANT_USER}@clients` },
    ],
    [
      'a tenant binding for an unscoped user',
      { azp: TENANT_ON_UNSCOPED_USER, sub: `${TENANT_ON_UNSCOPED_USER}@clients` },
    ],
    ['a disabled client', { azp: DISABLED_CLIENT, sub: `${DISABLED_CLIENT}@clients` }],
    ['an unknown client', { azp: 'unknown-client', sub: 'unknown-client@clients' }],
    ['a subject mismatch', { sub: 'human-user' }],
    ['an audience mismatch', { aud: 'https://other.example.com' }],
    ['an issuer mismatch', { iss: 'https://issuer.example.com' }],
    ['an expired token', { exp: Math.floor(Date.now() / 1000) - 30 }],
    ['conflicting client ids', { azp: UNSCOPED_CLIENT, client_id: 'other-client' }],
    ['a missing client id', { azp: undefined, client_id: undefined }],
  ])('denies %s', async (_label, claims) => {
    const { req, res, continued } = await authenticate(signToken(claims));

    expect(continued).toBe(false);
    expect(res.statusCode).toBe(401);
    expect(req.user).toBeUndefined();
  });

  it('denies a malformed bearer token before a user lookup', async () => {
    const findUser = jest.fn(methods.findUser);
    const req = createRequest('not-a-token');
    const res = createResponse();
    const next = jest.fn();
    await createAgentManagementAuth({
      findUser,
      isPrincipalActive: methods.isAgentTriggerPrincipalActive,
      getAppConfig: async () => parseManagementConfig(clients()),
    })(req, res, next);

    expect(findUser).not.toHaveBeenCalled();
    expect(res.statusCode).toBe(401);
    expect(next).not.toHaveBeenCalled();
  });

  it('denies an unscoped binding when strict isolation is on', async () => {
    process.env.TENANT_ISOLATION_STRICT = 'true';
    resetTenantStrictCache();
    try {
      const { res, continued } = await authenticate(signToken());
      expect(continued).toBe(false);
      expect(res.statusCode).toBe(401);
    } finally {
      delete process.env.TENANT_ISOLATION_STRICT;
      resetTenantStrictCache();
    }
  });
});

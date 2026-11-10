import mongoose from 'mongoose';
import { MongoMemoryServer } from 'mongodb-memory-server';
import {
  createMethods,
  createModels,
  getTenantId,
  resetTenantStrictCache,
  tenantStorage,
} from '@librechat/data-schemas';
import type { AllMethods, AppConfig, IUser } from '@librechat/data-schemas';
import type { Request, Response } from 'express';
import { createAgentManagementAuth } from './management';

const CLIENT_ID = 'machine-client';
const TENANT_ID = 'tenant-a';
const OTHER_TENANT_ID = 'tenant-b';

let mongoServer: MongoMemoryServer | undefined;
let methods: AllMethods;
let User: mongoose.Model<IUser>;
let originalStrictMode: string | undefined;

function createConfig(userId: string, tenantId: string): AppConfig {
  return {
    endpoints: {
      agents: {
        managementApi: {
          auth: {
            oidc: {
              enabled: true,
              issuer: 'https://issuer.example.com',
              audience: 'https://agents.example.com',
            },
            clients: [{ clientId: CLIENT_ID, userId, tenantId, enabled: true }],
          },
        },
      },
    },
  } as AppConfig;
}

function createRequest(): Request {
  return { headers: { authorization: 'Bearer signed-access-token' } } as Request;
}

function createResponse(): Response {
  const res = {
    status: jest.fn(),
    json: jest.fn(),
  };
  res.status.mockReturnValue(res);
  res.json.mockReturnValue(res);
  return res as unknown as Response;
}

beforeAll(async () => {
  originalStrictMode = process.env.TENANT_ISOLATION_STRICT;
  process.env.TENANT_ISOLATION_STRICT = 'true';
  resetTenantStrictCache();
  mongoServer = await MongoMemoryServer.create();
  await mongoose.connect(mongoServer.getUri());
  createModels(mongoose);
  methods = createMethods(mongoose);
  User = mongoose.models.User as mongoose.Model<IUser>;
});

afterAll(async () => {
  if (originalStrictMode == null) {
    delete process.env.TENANT_ISOLATION_STRICT;
  } else {
    process.env.TENANT_ISOLATION_STRICT = originalStrictMode;
  }
  resetTenantStrictCache();
  await mongoose.disconnect();
  await mongoServer?.stop();
});

beforeEach(async () => {
  await mongoose.connection.dropDatabase();
});

describe('Agent Management principal resolution with tenant isolation', () => {
  it('loads a bound User only from the configured tenant', async () => {
    const user = await tenantStorage.run({ tenantId: TENANT_ID }, () =>
      User.create({
        email: 'integration@example.com',
        name: 'Integration',
        username: 'integration',
        provider: 'local',
        role: 'USER',
        tenantId: TENANT_ID,
      }),
    );
    const userId = user._id.toString();
    const verifyAccessToken = jest.fn().mockResolvedValue({
      sub: `${CLIENT_ID}@clients`,
      azp: CLIENT_ID,
      exp: Math.floor(Date.now() / 1000) + 60,
    });
    let downstreamTenant: string | undefined;
    const validRequest = createRequest();
    const validResponse = createResponse();
    const validAuth = createAgentManagementAuth({
      findUser: methods.findUser,
      isPrincipalActive: methods.isAgentTriggerPrincipalActive,
      getAppConfig: jest.fn().mockResolvedValue(createConfig(userId, TENANT_ID)),
      verifyAccessToken,
    });

    await validAuth(validRequest, validResponse, () => {
      downstreamTenant = getTenantId();
    });

    expect(downstreamTenant).toBe(TENANT_ID);
    expect((validRequest as Request & { user?: IUser }).user).toMatchObject({
      id: userId,
      tenantId: TENANT_ID,
    });
    expect(validResponse.status).not.toHaveBeenCalled();

    const crossTenantResponse = createResponse();
    const crossTenantNext = jest.fn();
    const crossTenantAuth = createAgentManagementAuth({
      findUser: methods.findUser,
      isPrincipalActive: methods.isAgentTriggerPrincipalActive,
      getAppConfig: jest.fn().mockResolvedValue(createConfig(userId, OTHER_TENANT_ID)),
      verifyAccessToken,
    });

    await crossTenantAuth(createRequest(), crossTenantResponse, crossTenantNext);

    expect(crossTenantResponse.status).toHaveBeenCalledWith(401);
    expect(crossTenantNext).not.toHaveBeenCalled();
  });

  it('rejects an unscoped binding in strict mode before reading a legacy user', async () => {
    const findUser = jest.fn(methods.findUser);
    const response = createResponse();
    const next = jest.fn();
    const auth = createAgentManagementAuth({
      findUser,
      isPrincipalActive: methods.isAgentTriggerPrincipalActive,
      getAppConfig: jest.fn().mockResolvedValue({
        endpoints: {
          agents: {
            managementApi: {
              auth: {
                oidc: {
                  enabled: true,
                  issuer: 'https://issuer.example.com',
                  audience: 'https://agents.example.com',
                },
                clients: [
                  {
                    clientId: CLIENT_ID,
                    userId: '507f1f77bcf86cd799439011',
                    enabled: true,
                  },
                ],
              },
            },
          },
        },
      } as AppConfig),
      verifyAccessToken: jest.fn().mockResolvedValue({
        sub: `${CLIENT_ID}@clients`,
        azp: CLIENT_ID,
        exp: Math.floor(Date.now() / 1000) + 60,
      }),
    });

    await auth(createRequest(), response, next);

    expect(findUser).not.toHaveBeenCalled();
    expect(response.status).toHaveBeenCalledWith(401);
    expect(next).not.toHaveBeenCalled();
  });
});

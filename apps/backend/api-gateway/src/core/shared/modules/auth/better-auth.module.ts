import { passkey } from "@better-auth/passkey";
import { UniqueEntityId } from "@tamtt-labs/ddd";
import { drizzleAdapter } from "better-auth/adapters/drizzle";
import { betterAuth as betterAuthFactory } from "better-auth/minimal";
import { anonymous, openAPI, organization } from "better-auth/plugins";
import { emailOTP } from "better-auth/plugins/email-otp";
import Elysia from "elysia";
import { ConfigModule } from "../config/config.module";
import { DrizzleWriteModule } from "../database/drizzle.module";
import { authSchema } from "./schema";

export const BetterAuthModule = new Elysia({ name: "BetterAuthModule" })
  .use(ConfigModule)
  .use(DrizzleWriteModule.register("authRepository", authSchema))
  .resolve((context) => {
    // Extract domain from APP_ORIGIN for passkey rpID
    const appUrl = new URL(context.configService.get("APP_ORIGIN"));
    const rpID = appUrl.hostname;
    const basePath = "/auth";

    const betterAuth = betterAuthFactory({
      appName: context.configService.get("APP_NAME"),
      secret: context.configService.get("AUTH_SECRET"),
      trustedOrigins: [context.configService.get("APP_ORIGIN")],
      baseURL: context.configService.get("APP_ORIGIN"),
      basePath,

      database: drizzleAdapter(context.authRepository, {
        provider: "pg",
      }),

      account: {
        modelName: "identity",
      },

      // Email and password authentication
      emailAndPassword: {
        enabled: true,
        sendResetPassword: async () => {
          // await sendPasswordReset(env, { user, url });
        },
      },

      // Email verification
      emailVerification: {
        sendVerificationEmail: async () => {
          // await sendVerificationEmail(env, { user, url });
        },
      },

      // OAuth providers
      // socialProviders: {
      //   google: {
      //     clientId: context.configService.get("GOOGLE_CLIENT_ID"),
      //     clientSecret: context.configService.get("GOOGLE_CLIENT_SECRET"),
      //   },
      // },

      plugins: [
        openAPI(),
        anonymous(),
        organization({
          allowUserToCreateOrganization: true,
          organizationLimit: 5,
          creatorRole: "owner",
        }),
        passkey({
          // rpID: Relying Party ID - domain name in production, 'localhost' for dev
          rpID,
          // rpName: Human-readable name for your app
          rpName: context.configService.get("APP_NAME"),
          // origin: URL where auth occurs (no trailing slash)
          origin: context.configService.get("APP_ORIGIN"),
        }),
        emailOTP({
          sendVerificationOTP: async () => {
            // await sendOTP(env, { email, otp, type });
          },
          otpLength: 6,
          allowedAttempts: 3,
          expiresIn: context.configService.get("AUTH_OTP_EXPIRES_IN") ?? 300, // 5 days
        }),
      ],

      advanced: {
        database: {
          generateId: () => new UniqueEntityId().toString(),
        },
      },

      cookies: {
        session: {
          expiresIn: context.configService.get("AUTH_SESSION_EXPIRES_IN") ?? 604800, // 7 days
          cacheMaxAge: context.configService.get("AUTH_SESSION_CACHE_MAX_AGE") ?? 300, // 5 days
        },
      },
    });

    let _schema: ReturnType<typeof betterAuth.api.generateOpenAPISchema>;
    const getSchema = async () => (_schema ??= betterAuth.api.generateOpenAPISchema());

    const betterAuthOpenApi = {
      getPaths: (prefix = basePath) =>
        getSchema().then(({ paths }) => {
          const reference: typeof paths = Object.create(null);

          for (const path of Object.keys(paths)) {
            const key = prefix + path;

            if (!paths[path]) {
              continue;
            }

            reference[key] = paths[path];

            for (const method of Object.keys(paths[path])) {
              const operation = (reference[key] as any)[method];
              operation.tags = ["Better Auth"];
            }
          }

          return reference;
        }) as Promise<any>,
      components: getSchema().then(({ components }) => components) as Promise<any>,
    } as const;

    return { betterAuth, betterAuthOpenApi };
  })
  .all("/auth/*", (context) => context.betterAuth.handler);

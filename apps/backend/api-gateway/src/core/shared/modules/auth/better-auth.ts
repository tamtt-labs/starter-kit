import { passkey } from "@better-auth/passkey";
import { UniqueEntityId } from "@tamtt-labs/ddd";
import { drizzleAdapter } from "better-auth/adapters/drizzle";
import { betterAuth as betterAuthFactory } from "better-auth/minimal";
import { anonymous, organization } from "better-auth/plugins";
import { emailOTP } from "better-auth/plugins/email-otp";
import { configService } from "../config/config.module";
import { database } from "../database/drizzle.module";
import { authSchema } from "./schema";

// Extract domain from APP_ORIGIN for passkey rpID
const appUrl = new URL(configService.get("APP_ORIGIN"));
const rpID = appUrl.hostname;

export const betterAuth = betterAuthFactory({
  appName: configService.get("APP_NAME"),
  secret: configService.get("AUTH_SECRET"),
  trustedOrigins: [configService.get("APP_ORIGIN")],
  baseURL: configService.get("APP_ORIGIN"),
  basePath: "/auth",

  database: drizzleAdapter(database.write, {
    provider: "pg",
    schema: authSchema,
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
  //     clientId: configService.get("GOOGLE_CLIENT_ID"),
  //     clientSecret: configService.get("GOOGLE_CLIENT_SECRET"),
  //   },
  // },

  plugins: [
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
      rpName: configService.get("APP_NAME"),
      // origin: URL where auth occurs (no trailing slash)
      origin: configService.get("APP_ORIGIN"),
    }),
    emailOTP({
      sendVerificationOTP: async () => {
        // await sendOTP(env, { email, otp, type });
      },
      otpLength: 6,
      allowedAttempts: 3,
      expiresIn: configService.get("AUTH_OTP_EXPIRES_IN"),
    }),
  ],

  advanced: {
    database: {
      generateId: () => new UniqueEntityId().toString(),
    },
  },

  cookies: {
    session: {
      expiresIn: configService.get("AUTH_SESSION_EXPIRES_IN"),
      cacheMaxAge: configService.get("AUTH_SESSION_CACHE_MAX_AGE"),
    },
  },
});

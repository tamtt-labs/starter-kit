import { AppModule } from "./core/app.module";
import { configService } from "./core/shared/modules/config/config.module";

const bootstrap = async () => {
  const app = AppModule.listen(configService.get("APP_PORT"));
  const rootUrl = `http://${app.server?.hostname}:${app.server?.port}`;
  console.log(`🦊 ~ Elysia is running at ${rootUrl}`);
  console.log(`🦊 ~ OpenAPI is running at ${rootUrl}/openapi`);
};

await bootstrap();

export type ApiGateway = typeof AppModule;

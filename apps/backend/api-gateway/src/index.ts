import { AppModule } from "./core/app.module";
import { ConfigModule } from "./core/shared/modules/config/config.module";

export const bootstrap = async () => {
  const configService = ConfigModule.decorator.configService;

  const app = AppModule.listen(configService.get("PORT"));

  console.log(`🦊 Elysia is running at ${app.server?.hostname}:${app.server?.port}`);
};

await bootstrap();

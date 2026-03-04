import { AppModule } from "./core/app.module";
import { configService } from "./core/shared/modules/config/config.module";

export const bootstrap = async () => {
  const app = AppModule.listen(configService.get("APP_PORT"));
  console.log(`🦊 ~ Elysia is running at http://${app.server?.hostname}:${app.server?.port}`);
};

await bootstrap();

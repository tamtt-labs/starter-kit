import Elysia from "elysia";
import { CloudflareAdapter } from "elysia/adapter/cloudflare-worker";
import { AppModule } from "./core/app.module";

const CloudflareWorker = new Elysia({
  adapter: CloudflareAdapter,
})
  .use(AppModule)
  .compile();

export default CloudflareWorker;

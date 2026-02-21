import type { EventPublisher } from "@/event-publisher";
import type { ICommandHandler } from "@/interfaces";
import type { HeroRepository } from "../repositories/hero.repository";

export class KillDragonCommand {
  constructor(
    public readonly heroId: string,
    public readonly dragonId: string,
  ) {}
}

export class KillDragonHandler implements ICommandHandler<KillDragonCommand> {
  readonly command = KillDragonCommand;

  constructor(
    private readonly repository: HeroRepository,
    private readonly publisher: EventPublisher,
  ) {}

  async execute(command: KillDragonCommand) {
    console.log("🚀 ~ KillDragonHandler ~ execute ~ command:", command.constructor.name);

    const { heroId, dragonId } = command;
    const hero = this.publisher.mergeObjectContext(await this.repository.findOneById(heroId));
    hero.killEnemy(dragonId);
    hero.commit();
  }
}

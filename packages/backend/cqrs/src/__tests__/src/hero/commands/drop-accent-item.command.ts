import type { EventPublisher } from "@/event-publisher";
import type { ICommandHandler } from "@/interfaces";
import type { HeroRepository } from "../repositories/hero.repository";

export class DropAncientItemCommand {
  constructor(
    public readonly heroId: string,
    public readonly itemId: string,
  ) {}
}

export class DropAncientItemHandler implements ICommandHandler<DropAncientItemCommand> {
  readonly command = DropAncientItemCommand;

  constructor(
    private readonly repository: HeroRepository,
    private readonly publisher: EventPublisher,
  ) {}

  async execute(command: DropAncientItemCommand) {
    console.log("🚀 ~ DropAncientItemHandler ~ execute ~ command:", command.constructor.name);

    const { heroId, itemId } = command;
    const hero = this.publisher.mergeObjectContext(await this.repository.findOneById(heroId));
    hero.addItem(itemId);
    hero.commit();
  }
}

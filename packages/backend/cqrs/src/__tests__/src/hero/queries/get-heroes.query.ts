import type { IQueryHandler } from "@/interfaces";
import type { HeroRepository } from "../repositories/hero.repository";

export class GetHeroesQuery {}

export class GetHeroesHandler implements IQueryHandler<GetHeroesQuery> {
  readonly query = GetHeroesQuery;

  constructor(private readonly repository: HeroRepository) {}

  async execute(query: GetHeroesQuery) {
    console.log("🚀 ~ GetHeroesHandler ~ execute ~ query:", query.constructor.name);
    return this.repository.findAll();
  }
}

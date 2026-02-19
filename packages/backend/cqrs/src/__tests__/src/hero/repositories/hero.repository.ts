import { Hero } from "../entities/hero.aggregate-root";

export const HERO_ID = "1234";

export const userHero = new Hero(HERO_ID);

export class HeroRepository {
  async findOneById(_id: string): Promise<Hero> {
    return userHero;
  }

  async findAll(): Promise<Hero[]> {
    return [userHero];
  }
}

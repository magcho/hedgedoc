/*
 * SPDX-FileCopyrightText: 2021 The HedgeDoc developers (see AUTHORS file)
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

import {
  Column,
  Entity,
  ManyToOne,
  OneToMany,
  PrimaryGeneratedColumn,
} from 'typeorm';
import { Authorship } from '../revisions/authorship.entity';
import { Session } from '../users/session.entity';
import { User } from '../users/user.entity';

export type AuthorColor = number;

@Entity()
export class Author {
  @PrimaryGeneratedColumn()
  id: number;

  /**
   * The id of the color of this author
   * The application maps the id to an actual color
   */
  @Column({ type: 'int' })
  color: AuthorColor;

  @OneToMany(() => Session, (session) => session.author)
  sessions: Session[];

  @ManyToOne(() => User, (user) => user.authors, { nullable: true })
  user: User | null;

  @OneToMany(() => Authorship, (authorship) => authorship.author)
  authorships: Authorship[];

  // eslint-disable-next-line @typescript-eslint/no-empty-function
  private constructor() {}

  public static create(color: number) {
    const newAuthor = new Author();
    newAuthor.color = color;
    return newAuthor;
  }
}

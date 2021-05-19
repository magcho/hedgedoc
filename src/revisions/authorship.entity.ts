/*
 * SPDX-FileCopyrightText: 2021 The HedgeDoc developers (see AUTHORS file)
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

import {
  Column,
  CreateDateColumn,
  Entity,
  ManyToMany,
  ManyToOne,
  PrimaryGeneratedColumn,
  UpdateDateColumn,
} from 'typeorm';
import { Author } from '../authors/author.entity';
import { User } from '../users/user.entity';
import { Revision } from './revision.entity';

/**
 * This class stores which parts of a revision were edited by a particular user.
 */
@Entity()
export class Authorship {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  /**
   * Revisions this authorship appears in
   */
  @ManyToMany((_) => Revision, (revision) => revision.authorships)
  revisions: Revision[];

  /**
   * User this authorship represents
   */
  @ManyToOne((_) => User)
  user: User;

  @ManyToOne(() => Author, (author) => author.authorships)
  author: Author;

  @Column()
  startPos: number;

  @Column()
  endPos: number;

  @CreateDateColumn()
  createdAt: Date;

  @UpdateDateColumn()
  updatedAt: Date;

  // eslint-disable-next-line @typescript-eslint/no-empty-function
  private constructor() {}

  public static create(author: Author, startPos: number, endPos: number) {
    const newAuthorship = new Authorship();
    newAuthorship.author = author;
    newAuthorship.startPos = startPos;
    newAuthorship.endPos = endPos;
    return newAuthorship;
  }
}

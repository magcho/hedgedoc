/*
 * SPDX-FileCopyrightText: 2021 The HedgeDoc developers (see AUTHORS file)
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

import {
  Column,
  Entity,
  JoinTable,
  ManyToMany,
  ManyToOne,
  OneToMany,
  PrimaryGeneratedColumn,
} from 'typeorm';
import { NoteGroupPermission } from '../permissions/note-group-permission.entity';
import { NoteUserPermission } from '../permissions/note-user-permission.entity';
import { Revision } from '../revisions/revision.entity';
import { User } from '../users/user.entity';
import { Tag } from './tag.entity';
import { HistoryEntry } from '../history/history-entry.entity';
import { MediaUpload } from '../media/media-upload.entity';
import { generatePublicId } from './utils';

@Entity()
export class Note {
  @PrimaryGeneratedColumn('uuid')
  id: string;
  @Column({ type: 'text' })
  publicId: string;
  @Column({
    unique: true,
    nullable: true,
    type: 'text',
  })
  alias: string | null;
  @OneToMany(
    (_) => NoteGroupPermission,
    (groupPermission) => groupPermission.note,
    { cascade: true }, // This ensures that embedded NoteGroupPermissions are automatically saved to the database
  )
  groupPermissions: NoteGroupPermission[];
  @OneToMany(
    (_) => NoteUserPermission,
    (userPermission) => userPermission.note,
    { cascade: true }, // This ensures that embedded NoteUserPermission are automatically saved to the database
  )
  userPermissions: NoteUserPermission[];
  @Column({
    nullable: false,
    default: 0,
  })
  viewCount: number;
  @ManyToOne((_) => User, (user) => user.ownedNotes, {
    onDelete: 'CASCADE', // This deletes the Note, when the associated User is deleted
    nullable: true,
  })
  owner: User | null;
  @OneToMany((_) => Revision, (revision) => revision.note, { cascade: true })
  revisions: Promise<Revision[]>;
  @OneToMany((_) => HistoryEntry, (historyEntry) => historyEntry.user)
  historyEntries: HistoryEntry[];
  @OneToMany((_) => MediaUpload, (mediaUpload) => mediaUpload.note)
  mediaUploads: MediaUpload[];

  @Column({
    nullable: true,
    type: 'text',
  })
  description: string | null;
  @Column({
    nullable: true,
    type: 'text',
  })
  title: string | null;

  @ManyToMany((_) => Tag, (tag) => tag.notes, { eager: true, cascade: true })
  @JoinTable()
  tags: Tag[];

  // eslint-disable-next-line @typescript-eslint/no-empty-function
  private constructor() {}

  public static create(owner?: User, alias?: string): Note {
    const newNote = new Note();
    newNote.publicId = generatePublicId();
    newNote.alias = alias ?? null;
    newNote.viewCount = 0;
    newNote.owner = owner ?? null;
    newNote.userPermissions = [];
    newNote.groupPermissions = [];
    newNote.revisions = Promise.resolve([]) as Promise<Revision[]>;
    newNote.description = null;
    newNote.title = null;
    newNote.tags = [];
    return newNote;
  }
}

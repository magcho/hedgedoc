/*
 * SPDX-FileCopyrightText: 2021 The HedgeDoc developers (see AUTHORS file)
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

import { ConfigModule } from '@nestjs/config';
import { Test, TestingModule } from '@nestjs/testing';
import { getRepositoryToken } from '@nestjs/typeorm';
import mediaConfigMock from '../config/mock/media.config.mock';
import { LoggerModule } from '../logger/logger.module';
import { Note } from '../notes/note.entity';
import { NotesModule } from '../notes/notes.module';
import { Tag } from '../notes/tag.entity';
import { Authorship } from '../revisions/authorship.entity';
import { Revision } from '../revisions/revision.entity';
import { AuthToken } from '../auth/auth-token.entity';
import { Identity } from '../users/identity.entity';
import { User } from '../users/user.entity';
import { UsersModule } from '../users/users.module';
import { FilesystemBackend } from './backends/filesystem-backend';
import { BackendData, MediaUpload } from './media-upload.entity';
import { MediaService } from './media.service';
import { Repository } from 'typeorm';
import { promises as fs } from 'fs';
import { ClientError, NotInDBError } from '../errors/errors';
import { NoteGroupPermission } from '../permissions/note-group-permission.entity';
import { NoteUserPermission } from '../permissions/note-user-permission.entity';
import { Group } from '../groups/group.entity';
import appConfigMock from '../../src/config/mock/app.config.mock';

describe('MediaService', () => {
  let service: MediaService;
  let noteRepo: Repository<Note>;
  let userRepo: Repository<User>;
  let mediaRepo: Repository<MediaUpload>;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        MediaService,
        {
          provide: getRepositoryToken(MediaUpload),
          useClass: Repository,
        },
        FilesystemBackend,
      ],
      imports: [
        ConfigModule.forRoot({
          isGlobal: true,
          load: [mediaConfigMock, appConfigMock],
        }),
        LoggerModule,
        NotesModule,
        UsersModule,
      ],
    })
      .overrideProvider(getRepositoryToken(Authorship))
      .useValue({})
      .overrideProvider(getRepositoryToken(AuthToken))
      .useValue({})
      .overrideProvider(getRepositoryToken(Identity))
      .useValue({})
      .overrideProvider(getRepositoryToken(Note))
      .useClass(Repository)
      .overrideProvider(getRepositoryToken(Revision))
      .useValue({})
      .overrideProvider(getRepositoryToken(User))
      .useClass(Repository)
      .overrideProvider(getRepositoryToken(Tag))
      .useValue({})
      .overrideProvider(getRepositoryToken(NoteGroupPermission))
      .useValue({})
      .overrideProvider(getRepositoryToken(NoteUserPermission))
      .useValue({})
      .overrideProvider(getRepositoryToken(MediaUpload))
      .useClass(Repository)
      .overrideProvider(getRepositoryToken(Group))
      .useValue({})
      .compile();

    service = module.get<MediaService>(MediaService);
    noteRepo = module.get<Repository<Note>>(getRepositoryToken(Note));
    userRepo = module.get<Repository<User>>(getRepositoryToken(User));
    mediaRepo = module.get<Repository<MediaUpload>>(
      getRepositoryToken(MediaUpload),
    );
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('saveFile', () => {
    beforeEach(() => {
      const user = User.create('hardcoded', 'Testy') as User;
      const alias = 'alias';
      const note = Note.create(user, alias);
      jest.spyOn(userRepo, 'findOne').mockResolvedValueOnce(user);
      jest.spyOn(noteRepo, 'findOne').mockResolvedValueOnce(note);
    });

    it('works', async () => {
      const testImage = await fs.readFile('test/public-api/fixtures/test.png');
      let fileId = '';
      jest
        .spyOn(mediaRepo, 'save')
        .mockImplementationOnce(async (entry: MediaUpload) => {
          fileId = entry.id;
          return entry;
        });
      jest
        .spyOn(service.mediaBackend, 'saveFile')
        .mockImplementationOnce(
          async (
            buffer: Buffer,
            fileName: string,
          ): Promise<[string, BackendData]> => {
            expect(buffer).toEqual(testImage);
            return [fileName, null];
          },
        );
      const url = await service.saveFile(testImage, 'hardcoded', 'test');
      expect(url).toEqual(fileId);
    });

    describe('fails:', () => {
      it('MIME type not identifiable', async () => {
        await expect(
          service.saveFile(Buffer.alloc(1), 'hardcoded', 'test'),
        ).rejects.toThrow(ClientError);
      });

      it('MIME type not supported', async () => {
        const testText = await fs.readFile('test/public-api/fixtures/test.zip');
        await expect(
          service.saveFile(testText, 'hardcoded', 'test'),
        ).rejects.toThrow(ClientError);
      });
    });
  });

  describe('deleteFile', () => {
    it('works', async () => {
      const mockMediaUploadEntry = {
        id: 'testMediaUpload',
        backendData: 'testBackendData',
        user: {
          userName: 'hardcoded',
        } as User,
      } as MediaUpload;
      jest
        .spyOn(service.mediaBackend, 'deleteFile')
        .mockImplementationOnce(
          async (fileName: string, backendData: BackendData): Promise<void> => {
            expect(fileName).toEqual(mockMediaUploadEntry.id);
            expect(backendData).toEqual(mockMediaUploadEntry.backendData);
          },
        );
      jest
        .spyOn(mediaRepo, 'remove')
        .mockImplementationOnce(async (entry, _) => {
          expect(entry).toEqual(mockMediaUploadEntry);
          return entry;
        });
      await service.deleteFile(mockMediaUploadEntry);
    });
  });
  describe('findUploadByFilename', () => {
    it('works', async () => {
      const testFileName = 'testFilename';
      const userName = 'hardcoded';
      const backendData = 'testBackendData';
      const mockMediaUploadEntry = {
        id: 'testMediaUpload',
        backendData: backendData,
        user: {
          userName: userName,
        } as User,
      } as MediaUpload;
      jest
        .spyOn(mediaRepo, 'findOne')
        .mockResolvedValueOnce(mockMediaUploadEntry);
      const mediaUpload = await service.findUploadByFilename(testFileName);
      expect(mediaUpload.user.userName).toEqual(userName);
      expect(mediaUpload.backendData).toEqual(backendData);
    });
    it("fails: can't find mediaUpload", async () => {
      const testFileName = 'testFilename';
      jest.spyOn(mediaRepo, 'findOne').mockResolvedValueOnce(undefined);
      await expect(service.findUploadByFilename(testFileName)).rejects.toThrow(
        NotInDBError,
      );
    });
  });

  describe('listUploadsByUser', () => {
    describe('works', () => {
      it('with one upload from user', async () => {
        const mockMediaUploadEntry = {
          id: 'testMediaUpload',
          backendData: 'testBackendData',
          user: {
            userName: 'hardcoded',
          } as User,
        } as MediaUpload;
        jest
          .spyOn(mediaRepo, 'find')
          .mockResolvedValueOnce([mockMediaUploadEntry]);
        expect(
          await service.listUploadsByUser({ userName: 'hardcoded' } as User),
        ).toEqual([mockMediaUploadEntry]);
      });

      it('without uploads from user', async () => {
        jest.spyOn(mediaRepo, 'find').mockResolvedValueOnce([]);
        const mediaList = await service.listUploadsByUser({
          userName: 'hardcoded',
        } as User);
        expect(mediaList).toEqual([]);
      });
      it('with error (undefined as return value of find)', async () => {
        jest.spyOn(mediaRepo, 'find').mockResolvedValueOnce(undefined);
        const mediaList = await service.listUploadsByUser({
          userName: 'hardcoded',
        } as User);
        expect(mediaList).toEqual([]);
      });
    });
  });

  describe('listUploadsByNote', () => {
    describe('works', () => {
      it('with one upload to note', async () => {
        const mockMediaUploadEntry = {
          id: 'testMediaUpload',
          backendData: 'testBackendData',
          note: {
            id: '123',
          } as Note,
        } as MediaUpload;
        jest
          .spyOn(mediaRepo, 'find')
          .mockResolvedValueOnce([mockMediaUploadEntry]);
        const mediaList = await service.listUploadsByNote({
          id: '123',
        } as Note);
        expect(mediaList).toEqual([mockMediaUploadEntry]);
      });

      it('without uploads to note', async () => {
        jest.spyOn(mediaRepo, 'find').mockResolvedValueOnce([]);
        const mediaList = await service.listUploadsByNote({
          id: '123',
        } as Note);
        expect(mediaList).toEqual([]);
      });
      it('with error (undefined as return value of find)', async () => {
        jest.spyOn(mediaRepo, 'find').mockResolvedValueOnce(undefined);
        const mediaList = await service.listUploadsByNote({
          id: '123',
        } as Note);
        expect(mediaList).toEqual([]);
      });
    });
  });

  describe('removeNoteFromMediaUpload', () => {
    it('works', async () => {
      const mockMediaUploadEntry = {
        id: 'testMediaUpload',
        backendData: 'testBackendData',
        note: {
          alias: 'test',
        } as Note,
        user: {
          userName: 'hardcoded',
        } as User,
      } as MediaUpload;
      jest
        .spyOn(mediaRepo, 'save')
        .mockImplementationOnce(async (entry: MediaUpload) => {
          expect(entry.note).toBeNull();
          return entry;
        });
      await service.removeNoteFromMediaUpload(mockMediaUploadEntry);
      expect(mediaRepo.save).toHaveBeenCalled();
    });
  });
});

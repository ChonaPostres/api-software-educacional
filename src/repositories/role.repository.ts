import {inject} from '@loopback/core';
import {SlugRepositoryTitle} from '../lib/slug-repository.title';
import {MongoDataSource} from '../datasources';
import {Role} from '../models';

export class RoleRepository extends SlugRepositoryTitle<
  Role,
  typeof Role.prototype.id  > {
  constructor(
    @inject('datasources.mongo') dataSource: MongoDataSource,
  ) {
    super(Role, dataSource);
  }
}

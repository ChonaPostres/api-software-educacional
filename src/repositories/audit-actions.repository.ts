import {DefaultCrudRepository} from '@loopback/repository';
import {AuditActions, AuditActionsRelations} from '../models';
import {MongoDataSource} from '../datasources';
import {inject} from '@loopback/core';

export class AuditActionsRepository extends DefaultCrudRepository<
  AuditActions,
  typeof AuditActions.prototype.id,
  AuditActionsRelations
> {
  constructor(
    @inject('datasources.mongo') dataSource: MongoDataSource,
  ) {
    super(AuditActions, dataSource);
  }
}

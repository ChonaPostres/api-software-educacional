import {DefaultCrudRepository} from '@loopback/repository';
import {AuditAuthentication, AuditAuthenticationRelations} from '../models';
import {MongoDataSource} from '../datasources';
import {inject} from '@loopback/core';

export class AuditAuthenticationRepository extends DefaultCrudRepository<
  AuditAuthentication,
  typeof AuditAuthentication.prototype.id,
  AuditAuthenticationRelations
> {
  constructor(
    @inject('datasources.mongo') dataSource: MongoDataSource,
  ) {
    super(AuditAuthentication, dataSource);
  }
}

import {inject} from '@loopback/core';
import {DefaultCrudRepository} from '@loopback/repository';
import {MongoDataSource} from '../datasources';
import {RecoverPassword, RecoverPasswordRelations} from '../models';

export type CredentialsChangePassword = {
  email: string;
  password: string;
  hash: string;
};

export class RecoverPasswordRepository extends DefaultCrudRepository<
  RecoverPassword,
  typeof RecoverPassword.prototype.id,
  RecoverPasswordRelations
  > {
  constructor(
    @inject('datasources.mongo') dataSource: MongoDataSource,
  ) {
    super(RecoverPassword, dataSource);
  }
}

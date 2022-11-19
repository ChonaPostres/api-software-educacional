// Copyright IBM Corp. 2019. All Rights Reserved.
// Node module: loopback4-example-shopping
// This file is licensed under the MIT License.
// License text available at https://opensource.org/licenses/MIT

import {HttpErrors} from '@loopback/rest';
import {AuditActions, AuditAuthentication} from '../models';
import {Credentials} from '../repositories/user.repository';

export function validateCredentials(credentials: Credentials) {

  //Se comenta para permitir otros tipos de documentos
  /* const { validate, clean } = require('rut.js')


  // Validate Rut
  if (!validate(clean(credentials.rut))) {
  throw new HttpErrors.UnprocessableEntity('invalid rut');
  }
  */

  // Validate Password Length
  if (!credentials.password || credentials.password.length < 8) {
    throw new HttpErrors.UnprocessableEntity(
      'password must be minimum 8 characters',
    );
  }
}

export function completeZero(rut: string): string {
  let zeros = "000000000";
  rut = zeros.substr(0, zeros.length - rut.length) + rut;
  return rut;
}

export function completeZeroRuc(ruc: string): string {
  let zeros = "00000000";
  ruc = zeros.substr(0, zeros.length - ruc.length) + ruc;
  return ruc;
}

export function addZeroToDate(date: number): string {
  if (date < 10) {
    return "0" + date;
  }
  return date.toString();
}


export function registerAuditAuth(id: string, success: number): AuditAuthentication {
  var auditAuth: AuditAuthentication = new AuditAuthentication();
  auditAuth.success = success;
  auditAuth.user = id;
  return auditAuth;
}

export function registerAuditAction(id: string, action: string): AuditActions {
  var auditAction: AuditActions = new AuditActions();
  auditAction.action = action;
  auditAction.user = id;
  return auditAction;
}

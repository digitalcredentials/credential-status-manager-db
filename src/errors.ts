/*!
 * Copyright (c) 2024 Digital Credentials Consortium. All rights reserved.
 */
import { BaseCredentialStatusManager } from './credential-status-manager-base.js';

interface CustomErrorOptionalOptions {
  statusManager?: BaseCredentialStatusManager;
  message?: string;
}

interface CustomErrorRequiredOptions {
  defaultMessage: string;
  code: number;
}

type CustomErrorOptions = CustomErrorOptionalOptions & CustomErrorRequiredOptions;

export class CustomError extends Error {
  public code: number;

  constructor(options: CustomErrorOptions) {
    const { defaultMessage, code } = options;
    const message = `${options?.message ?? defaultMessage}`;
    super(message);
    this.code = code;
  }
}

export class BadRequestError extends CustomError {
  constructor(options?: CustomErrorOptionalOptions) {
    const { message } = options ?? {};
    const defaultMessage = 'That is an invalid request.';
    super({ message, defaultMessage, code: 400 });
  }
}

export class NotFoundError extends CustomError {
  constructor(options?: CustomErrorOptionalOptions) {
    const { message } = options ?? {};
    const defaultMessage = 'Resource not found.';
    super({ message, defaultMessage, code: 404 });
  }
}

export class InternalServerError extends CustomError {
  constructor(options?: CustomErrorOptionalOptions) {
    const { message } = options ?? {};
    const defaultMessage = 'The service encountered an internal error while processing your request.';
    super({ message, defaultMessage, code: 500 });
  }
}

export class WriteConflictError extends CustomError {
  constructor(options?: CustomErrorOptionalOptions) {
    const { message } = options ?? {};
    const defaultMessage = 'This operation conflicted with another operation.';
    super({ message, defaultMessage, code: 409 });
  }
}

export class InvalidDatabaseStateError extends CustomError {
  constructor(options?: CustomErrorOptionalOptions) {
    const { message } = options ?? {};
    const defaultMessage = 'The status database has an invalid state.';
    super({ message, defaultMessage, code: 500 });
  }
}

export class InvalidDidSeedError extends CustomError {
  constructor(options?: CustomErrorOptionalOptions) {
    const { message } = options ?? {};
    const defaultMessage = '"didSeed" must be a multibase-encoded value with at least 32 bytes.';
    super({ message, defaultMessage, code: 400 });
  }
}

export class InvalidCredentialsError extends CustomError {
  constructor(options?: CustomErrorOptionalOptions) {
    const { message } = options ?? {};
    const defaultMessage = 'The user credentials you are using to access the database is invalid.';
    super({ message, defaultMessage, code: 401 });
  }
}

export class MissingDatabaseError extends CustomError {
  constructor(options?: CustomErrorOptionalOptions) {
    const { statusManager, message } = options ?? {};
    const databaseName = statusManager?.getDatabaseName();
    const defaultMessage = `The database named "${databaseName}" must be manually created in advance.`;
    super({ message, defaultMessage, code: 400 });
  }
}

type MissingDatabaseTableErrorOptions = CustomErrorOptionalOptions & {
  missingTables?: string[];
}
export class MissingDatabaseTableError extends CustomError {
  constructor(options?: MissingDatabaseTableErrorOptions) {
    const { statusManager, message, missingTables } = options ?? {};
    const databaseTableNames = statusManager?.getDatabaseTableNames();
    let defaultMessage = 'The following database tables must be manually created in advance: ' +
      `${databaseTableNames?.map(t => `"${t}"`).join(', ')}.`;
    defaultMessage += missingTables ?
      ' However, the following tables have not yet been created: ' +
      `${missingTables?.map(t => `"${t}"`).join(', ')}.` :
      '';
    super({ message, defaultMessage, code: 400 });
  }
}

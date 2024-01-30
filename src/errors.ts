import { BaseCredentialStatusManager } from './credential-status-manager-base.js';

interface BaseErrorOptions {
  message: string;
}

interface ChildErrorOptions {
  message?: string;
  defaultMessage: string;
}

interface CustomErrorOptions {
  statusManager?: BaseCredentialStatusManager;
  message?: string;
}

class BaseError extends Error {
  public message: string;

  constructor(options: BaseErrorOptions) {
    const { message } = options;
    super(message);
    this.message = message;
  }
}

export class ChildError extends BaseError {
  constructor(options: ChildErrorOptions) {
    const { defaultMessage } = options;
    const message = `${options?.message ?? defaultMessage}`;
    super({ message });
  }
}

export class BadRequestError extends ChildError {
  constructor(options?: CustomErrorOptions) {
    const { message } = options ?? {};
    const defaultMessage = 'That is an invalid request.';
    super({ message, defaultMessage });
  }
}

export class NotFoundError extends ChildError {
  constructor(options?: CustomErrorOptions) {
    const { message } = options ?? {};
    const defaultMessage = 'Resource not found.';
    super({ message, defaultMessage });
  }
}

export class InternalServerError extends ChildError {
  constructor(options?: CustomErrorOptions) {
    const { message } = options ?? {};
    const defaultMessage = 'The service encountered an internal error while processing your request.';
    super({ message, defaultMessage });
  }
}

export class InvalidStateError extends ChildError {
  constructor(options?: CustomErrorOptions) {
    const { message } = options ?? {};
    const defaultMessage = 'The internal data has reached an invalid state.';
    super({ message, defaultMessage });
  }
}

export class InvalidDidSeedError extends ChildError {
  constructor(options?: CustomErrorOptions) {
    const { message } = options ?? {};
    const defaultMessage = '"didSeed" must be a multibase-encoded value with at least 32 bytes.';
    super({ message, defaultMessage });
  }
}

export class InvalidCredentialsError extends ChildError {
  constructor(options?: CustomErrorOptions) {
    const { message } = options ?? {};
    const defaultMessage = 'The username/password combination you are using to access the database is invalid.';
    super({ message, defaultMessage });
  }
}

export class MissingDatabaseError extends ChildError {
  constructor(options?: CustomErrorOptions) {
    const { statusManager, message } = options ?? {};
    const databaseName = statusManager?.getDatabaseName();
    const defaultMessage = `The database named "${databaseName}" must be manually created in advance.`;
    super({ message, defaultMessage });
  }
}

type MissingDatabaseTableErrorOptions = CustomErrorOptions & {
  missingTables?: string[];
}
export class MissingDatabaseTableError extends ChildError {
  constructor(options?: MissingDatabaseTableErrorOptions) {
    const { statusManager, message, missingTables } = options ?? {};
    const databaseTableNames = statusManager?.getDatabaseTableNames();
    let defaultMessage = 'The following database tables must be manually created in advance: ' +
      `${databaseTableNames?.map(t => `"${t}"`).join(', ')}.`;
    defaultMessage += missingTables ?
      ' However, the following tables have not yet been created: ' +
      `${missingTables?.map(t => `"${t}"`).join(', ')}.` :
      '';
    super({ message, defaultMessage });
  }
}

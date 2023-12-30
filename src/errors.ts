import { BaseCredentialStatusManager } from './credential-status-manager-base.js';

interface BaseErrorOptions {
  statusManager?: BaseCredentialStatusManager;
  message: string;
}

interface ChildErrorOptions {
  statusManager?: BaseCredentialStatusManager;
  message?: string;
  defaultMessage: string;
  label: string;
}

interface CustomErrorOptions {
  statusManager?: BaseCredentialStatusManager;
  message?: string;
}

class BaseError extends Error {
  public statusManager: BaseCredentialStatusManager | undefined;
  public message: string;

  constructor(options: BaseErrorOptions) {
    const { statusManager, message } = options;
    super(message);
    this.statusManager = statusManager;
    this.message = message;
  }
}

class ChildError extends BaseError {
  constructor(options: ChildErrorOptions) {
    const { statusManager, defaultMessage, label } = options;
    const message = `[${label}] ${options?.message ?? defaultMessage}`;
    super({ statusManager, message });
  }
}

export class BadRequestError extends ChildError {
  constructor(options?: CustomErrorOptions) {
    const { statusManager, message } = options ?? {};
    const defaultMessage = 'That is an invalid request.';
    const label = 'BadRequestError';
    super({ statusManager, message, defaultMessage, label });
  }
}

export class NotFoundError extends ChildError {
  constructor(options?: CustomErrorOptions) {
    const { statusManager, message } = options ?? {};
    const defaultMessage = 'Resource not found.';
    const label = 'NotFoundError';
    super({ statusManager, message, defaultMessage, label });
  }
}

export class InvalidStateError extends ChildError {
  constructor(options?: CustomErrorOptions) {
    const { statusManager, message } = options ?? {};
    const defaultMessage = 'The internal data has reached an invalid state.';
    const label = 'InvalidStateError';
    super({ statusManager, message, defaultMessage, label });
  }
}

export class InvalidDidSeedError extends ChildError {
  constructor(options?: CustomErrorOptions) {
    const { statusManager, message } = options ?? {};
    const defaultMessage = '"didSeed" must be a multibase-encoded value with at least 32 bytes.';
    const label = 'InvalidDidSeedError';
    super({ statusManager, message, defaultMessage, label });
  }
}

export class InvalidCredentialsError extends ChildError {
  constructor(options?: CustomErrorOptions) {
    const { statusManager, message } = options ?? {};
    const defaultMessage = 'The username/password combination you are using to access the database is invalid.';
    const label = 'InvalidCredentialsError';
    super({ statusManager, message, defaultMessage, label });
  }
}

export class MissingDatabaseError extends ChildError {
  constructor(options?: CustomErrorOptions) {
    const { statusManager, message } = options ?? {};
    const databaseName = statusManager?.getDatabaseName();
    const defaultMessage = `The database named "${databaseName}" must be manually created in advance.`;
    const label = 'MissingDatabaseError';
    super({ statusManager, message, defaultMessage, label });
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
    const label = 'MissingDatabaseTableError';
    super({ statusManager, message, defaultMessage, label });
  }
}

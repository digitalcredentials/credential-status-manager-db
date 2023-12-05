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

export class InvalidDidSeedError extends ChildError {
  constructor(options?: CustomErrorOptions) {
    const { statusManager, message } = options ?? {};
    const defaultMessage = '"didSeed" must be a multibase-encoded value with at least 32 bytes.';
    const label = 'InvalidDidSeedError';
    super({ statusManager, message, defaultMessage, label });
  }
}

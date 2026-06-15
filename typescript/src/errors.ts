/**
 * Base error for all KSwitch SDK errors.
 */
export class KSwitchError extends Error {
  public readonly statusCode: number;
  public readonly body: unknown;

  constructor(message: string, statusCode: number = 0, body?: unknown) {
    super(message);
    this.name = "KSwitchError";
    this.statusCode = statusCode;
    this.body = body;
    // Maintain proper prototype chain for instanceof checks
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

/**
 * Authentication / authorization error (401 / 403).
 */
export class AuthError extends KSwitchError {
  constructor(message: string = "Authentication failed", statusCode: number = 401, body?: unknown) {
    super(message, statusCode, body);
    this.name = "AuthError";
  }
}

/**
 * Resource not found (404).
 */
export class NotFoundError extends KSwitchError {
  constructor(message: string = "Resource not found", body?: unknown) {
    super(message, 404, body);
    this.name = "NotFoundError";
  }
}

/**
 * Validation / bad request (400 / 422).
 */
export class ValidationError extends KSwitchError {
  public readonly errors: unknown[];

  constructor(message: string = "Validation error", body?: unknown, errors: unknown[] = []) {
    super(message, 422, body);
    this.name = "ValidationError";
    this.errors = errors;
  }
}

/**
 * Rate limited (429).
 */
export class RateLimitError extends KSwitchError {
  public readonly retryAfter?: number;

  constructor(message: string = "Rate limit exceeded", retryAfter?: number, body?: unknown) {
    super(message, 429, body);
    this.name = "RateLimitError";
    this.retryAfter = retryAfter;
  }
}

/**
 * Server error (500+).
 */
export class ServerError extends KSwitchError {
  constructor(message: string = "Internal server error", statusCode: number = 500, body?: unknown) {
    super(message, statusCode, body);
    this.name = "ServerError";
  }
}

/**
 * Network / timeout error (no HTTP response).
 */
export class NetworkError extends KSwitchError {
  constructor(message: string = "Network error", cause?: Error) {
    super(message, 0);
    this.name = "NetworkError";
    if (cause) this.cause = cause;
  }
}

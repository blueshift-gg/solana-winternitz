/** Stable codes for encoded-input and signature failures. */
export type ErrorCode = 'InvalidLength' | 'InvalidEncoding' | 'InvalidSignature';

const messages: Record<ErrorCode, string> = {
  InvalidLength: 'invalid byte length',
  InvalidEncoding: 'invalid encoding',
  InvalidSignature: 'invalid signature',
};

/** Use `code` for handling failures; messages explain them for humans. */
export class CryptoError extends Error {
  constructor(readonly code: ErrorCode, message: string = messages[code]) {
    super(message);
    this.name = 'CryptoError';
  }
}

/** Fill an entire buffer using a CSPRNG, or throw if entropy is unavailable. */
export type FillRandom = (bytes: Uint8Array) => void;

export type SigningErrorCode = 'Exists' | 'Missing' | 'Locked' | 'Corrupt' | 'LeafBelowMinimum' | 'InvalidLeaf' | 'Exhausted' | 'SaltsExhausted' | 'Random' | 'Unusable' | 'Io';

/** A signing or persistence failure; `code` is stable and `message` is explanatory. */
export class SigningError extends Error {
  constructor(readonly code: SigningErrorCode, message: string, options?: ErrorOptions) {
    super(message, options); this.name = 'SigningError';
  }
}

export function signingError(error: unknown, code: 'Io' | 'Random' = 'Io'): SigningError {
  return error instanceof SigningError ? error : new SigningError(code, error instanceof Error ? error.message : String(error), { cause: error });
}

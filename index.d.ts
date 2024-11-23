/**
 * Type definitions for @multiotp/genotp
 * Project: @multiotp/genotp
 * Definitions by: Erik Metz (https://github.com/erik-metz)
 */

declare module '@multiotp/genotp' {
  /**
   * Options for configuring OTP generation.
   */
  export interface OTPGeneratorOptions {
    /**
     * The cryptographic algorithm to use for generating OTP.
     * @default 'sha1'
     */
    algorithm?: string
    /**
     * The number of digits in the generated OTP.
     * @default 6
     */
    digits?: number
    /**
     * The time period for which the OTP is valid, in seconds.
     * @default 30
     */
    period?: number
    /**
     * The length of the secret key used for OTP generation.
     * @default 20
     */
    secretLength?: number
  }

  /**
   * Result of OTP generation.
   */
  export interface OTPGeneratedResult {
    /**
     * The generated OTP.
     */
    otp: string
    /**
     * The date and time at which the OTP expires.
     */
    expiresAt: Date
  }

  /**
   * Generates a one-time password (OTP) using the specified secret key and options.
   * @param secret The secret key used for OTP generation.
   * @param options Options for configuring OTP generation.
   * @returns An object containing the generated OTP and its expiration date.
   */
  export function generateOTP(
    secret: string,
    options?: OTPGeneratorOptions
  ): OTPGeneratedResult

  /**
   * Class for generating OTPs.
   * Constructor takes an optional configuration object.
   */
  export default class OTP {
    constructor(options?: {
      algorithm?: string
      bias?: number
      counter?: number
      digits?: number
      period?: number
      pincode?: string
      secret?: string
      seedtype?: string
      type?: string
      values?: number
    })

    /**
     * Generates one or more one-time passwords (OTPs) based on the configuration.
     * @param options Options for configuring OTP generation (optional).
     * @returns The generated OTP(s).
     */
    generate(options?: {
      algorithm?: string
      bias?: number
      counter?: number
      digits?: number
      period?: number
      pincode?: string
      secret?: string
      seedtype?: string
      type?: string
      values?: number
    }): string | string[]
  }
}

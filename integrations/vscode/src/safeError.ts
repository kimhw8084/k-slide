export class SafeKSlideError extends Error {
  constructor(message: string) {
    super(message)
    this.name = "SafeKSlideError"
  }
}

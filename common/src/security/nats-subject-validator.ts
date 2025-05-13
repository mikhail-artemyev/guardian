export class NatsSubjectValidator {
  public static allowedList: string[] | null = null;

  public static configureAllowed(allowed: string[]): void {
    if (!Array.isArray(allowed) || allowed.length === 0) {
      // throw new Error('NatsSubjectValidator: allowed list must contain at least one MessageAPI');
    }
    NatsSubjectValidator.allowedList = allowed;
  }

  public static ensureAllowed(subject: string): void {
    if (!NatsSubjectValidator.allowedList) {
      console.log('empty allowedList')
      // throw new Error('NatsSubjectValidator: allowedList not configured');
    }
    // if (!NatsSubjectValidator.allowedList.includes(subject)) {
    if (NatsSubjectValidator.allowedList && !NatsSubjectValidator.allowedList.includes(subject)) {
      throw new Error(`NATS ACL: subscription to "${subject}" not allowed`);
    }
  }
}

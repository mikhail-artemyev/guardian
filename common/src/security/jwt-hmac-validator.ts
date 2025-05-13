import * as crypto from 'crypto';
import * as jwt from 'jsonwebtoken';

export class JwtHmacValidator {
  private static readonly hmacSecret = (() => {
    const s = process.env.HMAC_SECRET;
    if (!s) throw new Error('HMAC_SECRET env not set');
    return s;
  })();
  private static readonly jwtPrivateKey = (() => {
    const k = process.env.JWT_PRIVATE_KEY;
    if (!k) throw new Error('JWT_PRIVATE_KEY env not set');
    return k;
  })();
  private static readonly jwtPublicKey = (() => {
    const k = process.env.JWT_PUBLIC_KEY;
    if (!k) throw new Error('JWT_PUBLIC_KEY env not set');
    return k;
  })();

  public static wrapEnvelope<T>(data: T): {
  data: T;
  token: string;
} {
    const payload = JSON.stringify(data);
    const hmac = crypto.createHmac('sha256', this.hmacSecret).update(payload).digest('hex');
    const token = jwt.sign({ hmac }, this.jwtPrivateKey, { algorithm: 'RS256' });
    return { data, token };
  }

  public static validateAndUnwrap<T>(env: {
  data: T;
  token: string;
}): T {
    if (!env.token) throw new Error('JWT token is missing in envelope');

    let decoded: any;
    try {
      decoded = jwt.verify(env.token, this.jwtPublicKey, { algorithms: ['RS256'] });
    } catch {
      throw new Error('Invalid or expired JWT token');
    }

    if (typeof decoded.hmac !== 'string') {
      throw new Error('HMAC claim missing in JWT');
    }

    const payload = JSON.stringify(env.data);
    const expected = crypto
      .createHmac('sha256', this.hmacSecret)
      .update(payload)
      .digest('hex');

    if (expected !== decoded.hmac) {
      throw new Error('HMAC does not match payload');
    }

    return env.data;
  }
}

import { NatsConnection, headers, Subscription } from 'nats';
import { GenerateUUIDv4 } from '@guardian/interfaces';
import { ZipCodec } from './zip-codec.js';
import { IMessageResponse } from '../models/index.js';
import { ForbiddenException } from '@nestjs/common';
import { JwtHmacValidator } from '../security/jwt-hmac-validator.js';

type CallbackFunction = (body: any, error?: string, code?: number) => void;

class MessageError extends Error {
    public code: number;

    constructor(message: any, code?: number) {
        super(message);
        this.code = code;
    }
}

/**
 * Nats service
 */
export abstract class NatsService {
    /**
     * messageQueueName
     */
    public abstract messageQueueName: string;

    /**
     * replySubject
     */
    public abstract replySubject: string;

    /**
     * jsonCodec
     */
    protected readonly codec;

    /**
     * connection
     */
    protected connection: NatsConnection;

    /**
     * responseCallbacksMap
     */
    protected responseCallbacksMap: Map<string, CallbackFunction> = new Map();
    private publishAllowed: string[] | null = null;
    private subscribeAllowed: string[] | null = null;

    constructor() {
        this.codec = ZipCodec();
        // this.codec = JSONCodec();
    }

    /**
     * Set configure
     */
    public configureACL(
        publishList: string[],
        subscribeList: string[],
    ): void {
        // if (!publishList.length) throw new Error('publishList must not be empty');
        this.publishAllowed = publishList;
        this.subscribeAllowed = subscribeList;
    }

    /**
     * Init
     */
    public async init(): Promise<void> {
        if (!this.connection) {
            throw new Error('Connection must set first');
        }
        this.connection.subscribe(this.replySubject, {
            callback: async (error, msg) => {
                if (!error) {
                    const messageId = msg.headers.get('messageId');
                    const serviceToken = msg.headers.get('serviceToken');
                    const fn = this.responseCallbacksMap.get(messageId);
                    if (fn) {
                        const message = (await this.codec.decode(msg.data)) as IMessageResponse<any>;
                        if (!message) {
                            fn(null)
                        } else {
                            try {
                                const data = JwtHmacValidator.validateAndUnwrap({data: message, token: serviceToken});
                                fn(message.body, message.error, message.code);
                            } catch (e: any) {
                                console.error('Reply validation failed:', e.message);
                                fn(null, e.message, 401);
                            }
                        }
                        this.responseCallbacksMap.delete(messageId)
                    }
                } else {
                    console.error(error);
                }
            }
        });
    }

    /**
     * Set connection
     * @param cn
     */
    public setConnection(cn: NatsConnection): NatsService {
        this.connection = cn;
        return this
    }

    /**
     * Publish
     * @param subject
     * @param data
     * @param replySubject
     */
    public async publish(subject: string, data?: unknown, replySubject?: string): Promise<void> {
        if (this.publishAllowed && !this.publishAllowed) throw new Error('Publish ACL not configured');
        if (this.publishAllowed && !this.publishAllowed.includes(subject)) {
            throw new Error(`Publish to "${subject}" not allowed`);
        }
        const { token } = JwtHmacValidator.wrapEnvelope(data);
        const opts: any = {
            serviceToken: token
        };

        if (replySubject) {
            opts.reply = replySubject;
        }

        this.connection.publish(subject, await this.codec.encode(data), opts);
    }

    /**
     * Subscribe
     * @param subject
     * @param cb
     */
    public subscribe(subject: string, cb: Function): Subscription {
        if (this.subscribeAllowed && !this.subscribeAllowed.includes(subject)) {
            throw new Error(`NATS ACL: subscription to "${subject}" not allowed`);
        }
        const sub = this.connection.subscribe(subject);

        const fn = async (_sub: Subscription) => {
            for await (const m of _sub) {
                try {
                    const serviceToken = m.headers.get('serviceToken')
                    const data = await this.codec.decode(m.data);
                    const { token } = JwtHmacValidator.validateAndUnwrap({data, token: serviceToken});
                    cb(data);
                } catch (e) {
                    console.error(e.message);
                }
            }
        }
        fn(sub);
        return sub;
    }

    /**
     * Send message
     * @param subject
     * @param data
     * @param isResponseCallback
     * @param externalMessageId
     */
    public sendMessage<T>(subject: string, data?: unknown, isResponseCallback: boolean = true, externalMessageId?: string): Promise<T> {
        if (this.publishAllowed && !this.publishAllowed) throw new Error('Publish ACL not configured');
        if (this.publishAllowed && !this.publishAllowed.includes(subject)) {
            throw new Error(`Publish to "${subject}" not allowed`);
        }

        const messageId = externalMessageId ?? GenerateUUIDv4();

        return new Promise(async (resolve, reject) => {
            const head = headers();
            head.append('messageId', messageId);
            if (isResponseCallback) {
                this.responseCallbacksMap.set(messageId, (body: T, error?: string, code?: number) => {
                    if (error) {
                        reject(new MessageError(error, code));
                    } else {
                        resolve(body);
                    }
                })
            } else {
                resolve(null);
            }

            const { token } = JwtHmacValidator.wrapEnvelope(data);
            head.append('serviceToken', token);

            this.connection.publish(subject, await this.codec.encode(data), {
                reply: this.replySubject,
                headers: head
            })
        });
    }

    /**
     * Send message with timeout
     * @param subject
     * @param timeout
     * @param data
     */
    public sendMessageWithTimeout<T>(subject: string, timeout: number, data?: unknown): Promise<T> {
        const messageId = GenerateUUIDv4();

        const messagePromise = this.sendMessage<T>(subject, data, true, messageId);

        const timeoutPromise = new Promise<T>((_, reject) => {
            setTimeout(() => {
                this.responseCallbacksMap.delete(messageId);
                reject(new Error(`Timeout exceed (${subject})`));
            }, timeout);
        });

        return Promise.race([messagePromise, timeoutPromise]);
    }

    /**
     * Send raw message
     * @param subject
     * @param data
     */
    public sendRawMessage<T>(subject: string, data?: unknown): Promise<T> {
        if (this.publishAllowed && !this.publishAllowed) throw new Error('Publish ACL not configured');
        if (this.publishAllowed && !this.publishAllowed.includes(subject)) {
            throw new Error(`Publish to "${subject}" not allowed`);
        }
        const messageId = GenerateUUIDv4();
        return new Promise(async (resolve, reject) => {
            const head = headers();
            head.append('messageId', messageId);
            // head.append('rawMessage', 'true');

            this.responseCallbacksMap.set(messageId, (body: T, error?: string, code?: number) => {
                if (error) {
                    reject(error);
                } else {
                    resolve(body);
                }
            })

            const { token } = JwtHmacValidator.wrapEnvelope(data);
            head.append('serviceToken', token);

            this.connection.publish(subject, await this.codec.encode(data), {
                reply: this.replySubject,
                headers: head
            })
        });
    }

    /**
     * Get messages
     * @param subject
     * @param cb
     * @param noRespond
     */
    public getMessages<T, A>(subject: string, cb: Function, noRespond = false): Subscription {
        return this.connection.subscribe(subject, {
            queue: this.messageQueueName,
            callback: async (error, msg) => {
                try {
                    const messageId = msg.headers?.get('messageId');
                    const serviceToken = msg.headers?.get('serviceToken');
                    // const isRaw = msg.headers.get('rawMessage');
                    const head = headers();
                    if (messageId) {
                        head.append('messageId', messageId);
                    }
                    // head.append('rawMessage', isRaw);
                    if (this.subscribeAllowed && !this.subscribeAllowed.includes(subject)) {
                        if (!noRespond) {
                            return msg.respond(await this.codec.encode({
                                body: null,
                                error: 'Forbidden',
                                code: 403,
                                name: 'Forbidden',
                                message: 'Forbidden'
                              }), { headers: head });
                        } else {
                            throw new ForbiddenException();
                        }
                    }

                    const data = await this.codec.decode(msg.data);
                    const { token } = JwtHmacValidator.validateAndUnwrap({data, token: serviceToken});

                    if (!noRespond) {
                        msg.respond(await this.codec.encode(await cb(await this.codec.decode(msg.data), msg.headers)), { headers: head });
                    } else {
                        cb(await this.codec.decode(msg.data), msg.headers);
                    }
                } catch (error) {
                    console.error(error);
                }
            }
        });
    }
}

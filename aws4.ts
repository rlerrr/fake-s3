import * as crypto from 'crypto';
import * as http from 'http';
import * as querystring from 'querystring';
import { DeepReadonly } from 'ts-essentials';

/*
Code adapted from https://www.npmjs.com/package/aws4
*/

// http://docs.amazonwebservices.com/general/latest/gr/signature-version-4.html
function hmac(key: any, string: any, encoding?: any) {
    return crypto.createHmac('sha256', key).update(string, 'utf8').digest(encoding)
}

function hash(string: any, encoding?: any) {
    return crypto.createHash('sha256').update(string, 'utf8').digest(encoding)
}

// This function assumes the string has already been percent encoded
function encodeRfc3986(urlEncodedString: string) {
    return urlEncodedString.replace(/[!'()*]/g, (c) => {
        return '%' + c.charCodeAt(0).toString(16).toUpperCase()
    })
}

function encodeRfc3986Full(str: string) {
    return encodeRfc3986(encodeURIComponent(str))
}

// A bit of a combination of:
// https://github.com/aws/aws-sdk-java-v2/blob/dc695de6ab49ad03934e1b02e7263abbd2354be0/core/auth/src/main/java/software/amazon/awssdk/auth/signer/internal/AbstractAws4Signer.java#L59
// https://github.com/aws/aws-sdk-js/blob/18cb7e5b463b46239f9fdd4a65e2ff8c81831e8f/lib/signers/v4.js#L191-L199
// https://github.com/mhart/aws4fetch/blob/b3aed16b6f17384cf36ea33bcba3c1e9f3bdfefd/src/main.js#L25-L34
const HEADERS_TO_IGNORE: Record<string, boolean> = {
    'authorization': true,
    'connection': true,
    'x-amzn-trace-id': true,
    'user-agent': true,
    'expect': true,
    'presigned-expires': true,
    'range': true
}

const QUERY_TO_IGNORE: Record<string, boolean> = {
    'x-amz-signature': true,
};

type Credentials = {
    readonly accessKeyId: string;
    readonly secretAccessKey: string;
    readonly sessionToken?: string;
}

export class RequestSigner {
    readonly body: Buffer;
    readonly request: DeepReadonly<http.IncomingMessage>;
    readonly service: string;
    readonly region: string;

    readonly parsedPath: {
        path: string,
        query: querystring.ParsedUrlQuery | null,
    };

    readonly credentials: Credentials;

    readonly filteredHeaders: (string | readonly string[] | undefined)[][];

    constructor(request: DeepReadonly<http.IncomingMessage>, body: Buffer, service: string, region: string, credentials: Credentials) {
        this.request = request;
        this.body = body;

        this.service = service;
        this.region = region;
        this.credentials = credentials;

        this.parsedPath = RequestSigner.parsePath(request);
        this.filteredHeaders = this.filterHeaders(request);
    }

    matchHost(host: string) {
        var match = (host || '').match(/([^\.]{1,63})\.(?:([^\.]{0,63})\.)?amazonaws\.com(\.cn)?$/)
        var hostParts = (match || []).slice(1, 3)

        // ES's hostParts are sometimes the other way round, if the value that is expected
        // to be region equals ‘es’ switch them back
        // e.g. search-cluster-name-aaaa00aaaa0aaa0aaaaaaa0aaa.us-east-1.es.amazonaws.com
        if (hostParts[1] === 'es' || hostParts[1] === 'aoss')
            hostParts = hostParts.reverse()

        if (hostParts[1] == 's3') {
            hostParts[0] = 's3'
            hostParts[1] = 'us-east-1'
        } else {
            for (var i = 0; i < 2; i++) {
                if (/^s3-/.test(hostParts[i])) {
                    hostParts[1] = hostParts[i].slice(3)
                    hostParts[0] = 's3'
                    break
                }
            }
        }

        return hostParts
    }

    parseDate(dateStr: string): Date {
        // Ensure the dateStr is in the expected format (YYYYMMDDTHHMMSSZ)
        const regex = /^(\d{4})(\d{2})(\d{2})T(\d{2})(\d{2})(\d{2})Z$/;
        const match = dateStr.match(regex);

        if (!match) {
            throw new Error('Invalid date format. Expected format: YYYYMMDDTHHMMSSZ');
        }

        const [_, year, month, day, hour, minute, second] = match;

        // Create a new Date object
        return new Date(Date.UTC(
            parseInt(year, 10),
            parseInt(month, 10) - 1, // Months are 0-indexed
            parseInt(day, 10),
            parseInt(hour, 10),
            parseInt(minute, 10),
            parseInt(second, 10)
        ));
    }

    getDateObj() {
        const headers = this.request.headers;
        const dateHeader = headers["x-amz-date"] || this.parsedPath.query?.["X-Amz-Date"];
        return dateHeader && typeof dateHeader === 'string' ? this.parseDate(dateHeader) : new Date();
    }

    getDateTime() {
        const date = this.getDateObj();
        return date.toISOString().replace(/[:\-]|\.\d{3}/g, '');
    }

    getDate() {
        return this.getDateTime().substr(0, 8)
    }

    authHeader() {
        return [
            'AWS4-HMAC-SHA256 Credential=' + this.credentials.accessKeyId + '/' + this.credentialString(),
            'SignedHeaders=' + this.signedHeaders(),
            'Signature=' + this.signature(),
        ].join(', ')
    }

    signature() {
        const date = this.getDate();
        const kDate = hmac('AWS4' + this.credentials.secretAccessKey, date);
        const kRegion = hmac(kDate, this.region);
        const kService = hmac(kRegion, this.service);
        const kCredentials = hmac(kService, 'aws4_request');

        return hmac(kCredentials, this.stringToSign(), 'hex');
    }

    stringToSign() {
        return [
            'AWS4-HMAC-SHA256',
            this.getDateTime(),
            this.credentialString(),
            hash(this.canonicalString(), 'hex'),
        ].join('\n')
    }

    canonicalString() {
        var pathStr = this.parsedPath.path,
            query = this.parsedPath.query,
            queryStr = '',
            normalizePath = this.service !== 's3',
            decodePath = this.service === 's3',
            decodeSlashesInPath = this.service === 's3',
            firstValOnly = this.service === 's3',
            bodyHash

        if (this.service === 's3' && (!this.request.headers.authorization || this.request.headers["x-amz-content-sha256"] === "UNSIGNED-PAYLOAD")) {
            bodyHash = 'UNSIGNED-PAYLOAD'
        } else {
            bodyHash = hash(this.body ?? '', 'hex')
        }

        if (query) {
            const reducedQuery = Object.keys(query).filter(k => !QUERY_TO_IGNORE[k.toLocaleLowerCase()]).reduce((obj, key) => {
                if (!key || !query) return obj;
                const value = query[key];
                if (value) {
                    obj[encodeRfc3986Full(key)] = !Array.isArray(value) ? value :
                        (firstValOnly ? value[0] : value)
                }
                return obj
            }, {} as Record<string, string | string[]>);

            const encodedQueryPieces: string[] = [];
            Object.keys(reducedQuery).sort().forEach((key) => {
                const val = reducedQuery[key];
                if (!Array.isArray(val)) {
                    encodedQueryPieces.push(key + '=' + encodeRfc3986Full(val))
                } else {
                    val.map(encodeRfc3986Full).sort()
                        .forEach((val) => { encodedQueryPieces.push(key + '=' + val) })
                }
            })
            queryStr = encodedQueryPieces.join('&')
        }
        if (pathStr !== '/') {
            if (normalizePath) pathStr = pathStr.replace(/\/{2,}/g, '/')
            pathStr = pathStr.split('/').reduce((path, piece) => {
                if (normalizePath && piece === '..') {
                    path.pop()
                } else if (!normalizePath || piece !== '.') {
                    if (decodePath) piece = decodeURIComponent(piece.replace(/\+/g, ' '))
                    path.push(encodeRfc3986Full(piece))
                }
                return path
            }, [] as string[]).join('/');
            if (pathStr[0] !== '/') pathStr = '/' + pathStr;
            if (decodeSlashesInPath) pathStr = pathStr.replace(/%2F/g, '/')
        }

        return [
            this.request.method || 'GET',
            pathStr,
            queryStr,
            this.canonicalHeaders(),
            '',
            this.signedHeaders(),
            bodyHash,
        ].join('\n')
    }

    filterHeaders(request: DeepReadonly<http.IncomingMessage>) {
        const headers = request.headers;
        let headersToInclude: string[] | undefined;

        if (this.service === 's3' && !this.request.headers.authorization) {
            headersToInclude = this.parsedPath.query?.["X-Amz-SignedHeaders"]?.toString()?.split(';');
        } else {
            headersToInclude = this.request.headers.authorization?.match(/SignedHeaders=([^,]+),/)?.[1]?.split(';');
        }

        headersToInclude = headersToInclude ?? Object.keys(request.headers);
        headersToInclude = headersToInclude.filter(h => !HEADERS_TO_IGNORE[h]);

        return headersToInclude
            .map((key): [string, string | readonly string[] | undefined] => [key.toLowerCase(), headers[key]])
            .sort((a, b) => a[0] < b[0] ? -1 : 1);
    }

    canonicalHeaders() {
        return this.filteredHeaders.map(([key, value]) => {
            let strValue: string;
            if (value instanceof Array)
                strValue = value.join(',');
            else
                strValue = value ?? '';

            if (key === 'host' && this.request.headers.authorization)
                strValue = strValue.split(':')[0];

            return key + ':' + strValue.trim().replace(/\s+/g, ' ');
        }).join('\n');
    }

    signedHeaders() {
        return this.filteredHeaders.map(([key]) => key).join(';');
    }

    credentialString() {
        return [
            this.getDate(),
            this.region,
            this.service,
            'aws4_request',
        ].join('/')
    }

    static parsePath(request: DeepReadonly<http.IncomingMessage>) {
        var path = request.url || '/'

        // S3 doesn't always encode characters > 127 correctly and
        // all services don't encode characters > 255 correctly
        // So if there are non-reserved chars (and it's not already all % encoded), just encode them all
        if (/[^0-9A-Za-z;,/?:@&=+$\-_.!~*'()#%]/.test(path)) {
            path = encodeURI(decodeURI(path))
        }

        var queryIx = path.indexOf('?'),
            query = null

        if (queryIx >= 0) {
            query = querystring.parse(path.slice(queryIx + 1))
            path = path.slice(0, queryIx)
        }

        return {
            path: path,
            query: query,
        }
    }

    formatPath() {
        var path = this.parsedPath.path,
            query = this.parsedPath.query

        if (!query) return path

        // Services don't support empty query string keys
        if (query[''] != null) delete query['']

        return path + '?' + encodeRfc3986(querystring.stringify(query))
    }

    isExpired(maxExpiration: number): boolean {
        let expiration: number;
        const expirationQs = this.parsedPath.query?.["X-Amz-Expires"] ?? this.request.headers["X-Amz-Expires"] ?? this.request.headers["x-amz-expires"];
        if (expirationQs instanceof Array) {
            expiration = parseInt(expirationQs[0]);
        } else if (expirationQs) {
            expiration = parseInt(expirationQs);
        } else {
            expiration = 15 * 60;
        }

        const finalExpiration = Math.min(Math.max(0, expiration), maxExpiration);
        return new Date().getTime() - this.getDateObj().getTime() > finalExpiration * 1000;
    }
}

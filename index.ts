import { strict as assert } from 'assert';
import * as fs from 'fs';
import * as http from 'http';
import * as path from 'path';
import * as url from 'url';
import * as util from 'util';
import { RequestSigner } from './aws4';

const mkdirP = util.promisify(fs.mkdir);
const writeFileP = util.promisify(fs.writeFile);
const readdirP = util.promisify(fs.readdir);
const statP = util.promisify(fs.stat);
const existsP = util.promisify(fs.exists);

const stripCreds = /Credential=([\w-/0-9a-zA-Z]+),/

type Callback = (err?: Error) => void;

type S3BucketOwner = {
  DisplayName: string,
  ID: string
};

type S3UserBucketConfig = {
  accessKeyId: string,
  secretAccessKey: string,
  buckets: S3BucketConfig[];
}

type S3BucketConfig = {
  name: string,
  path: string,
  versioning?: boolean
};

class NoSuchBucketError extends Error {
  readonly code = 'NoSuchBucket';
  readonly resource: string;

  constructor(message: string, bucket: string) {
    super(message);

    this.resource = bucket;
  }
}

class S3Object {
  readonly type = 's3-object';
  readonly bucket: string;
  readonly key: string;
  readonly lastModified: string;
  readonly md5: string;
  readonly contentLength: number;

  constructor(bucket: string, key: string, lastModified: string, md5: string, contentLength: number) {
    this.bucket = bucket;
    this.key = key;
    this.lastModified = lastModified;
    this.md5 = md5;
    this.contentLength = contentLength;
  }
}

class CommonPrefix {
  readonly type = 's3-common-prefix';
  readonly prefix: string;
  constructor(prefix: string) {
    this.prefix = prefix
  }
}

class S3Bucket {
  readonly name: string;
  readonly path: string;
  readonly versioning: boolean;

  constructor(name: string, path: string, versioning?: boolean) {
    this.name = name;
    this.path = path;
    this.versioning = versioning ?? false;
  }

  async addObject(obj: S3Object, buf: Buffer) {
    const filePath = this.getObjectPath(obj.key);
    if (this.versioning) {
      const exists = fs.existsSync(filePath);
      if (exists) {
        //Don't overwrite
        const existingStat = fs.statSync(filePath);
        const parsedPath = path.parse(filePath);
        let newFilePath = path.join(parsedPath.dir, `${parsedPath.name}.${existingStat.atime.getTime()}${parsedPath.ext}`);
        let count = 1;
        while (fs.existsSync(newFilePath)) {
          newFilePath = path.join(parsedPath.dir, `${parsedPath.name}.${existingStat.atime.getTime()}-${++count}${parsedPath.ext}`);
        }
        fs.renameSync(filePath, newFilePath);

        //Write w/o overwrite
        return await writeFileP(filePath, buf, { flag: "wx" });
      }
    }
    await writeFileP(filePath, buf);
  }

  getObjectPath(unsafeSuffix: string) {
    //See https://security.stackexchange.com/questions/123720/how-to-prevent-directory-traversal-when-joining-paths-in-node-js
    const safeSuffix = path.normalize(unsafeSuffix).replace(/^(\.\.(\/|\\|$))+/, '');
    return path.join(this.path, safeSuffix);
  }

  async getObjects(): Promise<S3Object[]> {
    const files = await readdirP(this.path, { recursive: true, withFileTypes: true });

    const result: S3Object[] = [];
    for (const file of files) {
      if (file.name === '.' || file.name === '..')
        continue;

      const fullPath = path.join(file.path, file.name);
      const key = path.relative(this.path, fullPath).replace(/\\/g, '/');
      const fileStat = await statP(fullPath);
      if (file.isFile())
        result.push(new S3Object(this.name, key, fileStat.mtime.toISOString(), "", fileStat.size));
    }
    return result;
  }
}

type FakeS3Options = {
  users?: S3UserBucketConfig[],
  hostname?: string,
  port?: number,
  waitTimeout?: number
};

type BucketProfile = {
  secretAccessKey: string;
  buckets: Map<string, S3Bucket>;
};

export default class FakeS3 {
  readonly requestPort: number;
  readonly requestHost: string;
  readonly waitTimeout: number;

  readonly httpServer: http.Server;
  hostPort: string | null;

  readonly start: number;

  readonly _profiles: Map<string, BucketProfile>;
  readonly _bucketOwnerInfo: Map<string, S3BucketOwner>;

  readonly tokens: Map<string, { offset: number, startAfter?: string }>;

  constructor(options: FakeS3Options) {
    assert(options, 'options required');
    assert(options.users, 'options.users  required');

    this.requestPort = typeof options.port === 'number' ? options.port : 0;
    this.requestHost = options.hostname || 'localhost';
    this.waitTimeout = options.waitTimeout || 5 * 1000;

    this.httpServer = http.createServer();
    this.hostPort = null;

    this.start = Date.now();

    this._profiles = FakeS3.setupBuckets(options.users ?? []);
    this._bucketOwnerInfo = new Map();
    this.tokens = new Map();
  }

  async bootstrap() {
    this.httpServer.on('request', (req, res) => {
      this._handleServerRequest(req, res)
    })

    await util.promisify((cb: Callback) => {
      this.httpServer.listen(this.requestPort, cb)
    })()

    const addr = this.httpServer.address()
    const port = (addr && typeof addr === 'object')
      ? addr.port : -1
    this.hostPort = `localhost:${port}`
  }

  getHostPort() {
    if (!this.hostPort) return ''
    return this.hostPort
  }

  async tryMkdir(filePath: string) {
    try {
      await mkdirP(filePath)
    } catch (err) {
      if (!err || typeof err !== 'object' || !("code" in err) || err.code !== 'EEXIST')
        throw err;
    }
  }

  static setupBuckets(users: S3UserBucketConfig[]) {
    const profiles: Map<string, BucketProfile> = new Map();
    for (const user of users) {
      const bucketsMap: Map<string, S3Bucket> = new Map();

      for (const bucket of user.buckets) {
        bucketsMap.set(bucket.name, new S3Bucket(bucket.name, bucket.path, bucket.versioning));
      }

      profiles.set(user.accessKeyId, { secretAccessKey: user.secretAccessKey, buckets: bucketsMap });
    }

    return profiles;
  }

  async close() {
    await util.promisify((cb: Callback) => {
      this.httpServer.close(cb)
    })()
  }

  async _handlePutObject(req: http.IncomingMessage, buf: Buffer, parsedUrl: url.UrlWithParsedQuery) {
    const parts = decodeURIComponent(parsedUrl.pathname || '').split('/')
    if (parts.length < 3 || parts[0] !== '') {
      throw new Error('invalid url, expected /:bucket/:key')
    }

    const bucket = parts[1]
    const key = parts.slice(2, parts.length).join('/')

    if (req.headers['x-amz-copy-source']) {
      throw new Error('copyObject() not supported')
    }
    if (parsedUrl.query.uploadId) {
      throw new Error('putObjectMultipart not supported')
    }

    // For the upload use case we always write into the default
    // profile and not into the profiles hydrated from cache.
    const bucketsMap = this._getBucketsMap(req, parsedUrl);
    const s3bucket = bucketsMap ? bucketsMap.get(bucket) : null
    if (!s3bucket) {
      const err = new NoSuchBucketError(
        'The specified bucket does not exist', bucket
      )
      throw err
    }

    const lastModified = new Date().toISOString()
    const obj = new S3Object(
      bucket, key, lastModified, '', buf.length
    )
    await s3bucket.addObject(obj, buf);
    return obj
  }

  _getBucketsMap(req: http.IncomingMessage, parsedUrl: url.UrlWithParsedQuery) {
    let profile;
    if (req.headers.authorization) {
      const match = req.headers.authorization.match(stripCreds);
      if (match) {
        const creds = match[0].slice(11)
        const accessKeyId = creds.split('/')[0]
        profile = accessKeyId
      }
    } else {
      let creds = parsedUrl.query['X-Amz-Credential'];
      if (Array.isArray(creds)) creds = creds[0];

      profile = creds?.split('/')[0];
    }

    if (!profile)
      throw new Error('Unauthorized');

    const info = this._profiles.get(profile);
    if (info) {
      return info.buckets;
    }

    throw new Error('Unauthorized');
  }

  _handleListBuckets(req: http.IncomingMessage, parsedUrl: url.UrlWithParsedQuery) {
    const bucketsMap = this._getBucketsMap(req, parsedUrl)
    const buckets = bucketsMap ? [...bucketsMap.keys()] : []

    let bucketsXML = ''

    const start = Math.floor(this.start / 1000)
    for (const b of buckets) {
      bucketsXML += `
        <Bucket>
          <CreationDate>${start}</CreationDate>
          <Name>${escapeXML(b)}</Name>
        </Bucket>
      `
    }

    const ownerInfo = this._bucketOwnerInfo.get(buckets[0])
    const displayName = ownerInfo ? ownerInfo.DisplayName : 'admin'
    const id = ownerInfo ? ownerInfo.ID : '1'

    return `<ListBucketsOutput>
      <Buckets>
        ${bucketsXML}
      </Buckets>
      <Owner>
        <DisplayName>${escapeXML(displayName)}</DisplayName>
        <ID>${escapeXML(id)}</ID>
      </Owner>
    </ListBucketsOutput>`
  }

  paginate(parsedUrl: url.UrlWithParsedQuery, rawObjects: (S3Object | CommonPrefix)[]) {
    let maxKeys = 1000

    if (parsedUrl.query['max-keys']) {
      let maxKeysStr = parsedUrl.query['max-keys']
      if (Array.isArray(maxKeysStr)) maxKeysStr = maxKeysStr[0]

      const queryMaxKeys = parseInt(maxKeysStr, 10)
      if (queryMaxKeys < maxKeys) {
        maxKeys = queryMaxKeys
      }
    }

    let offset = 0
    let startAfter = parsedUrl.query['start-after']
    if (Array.isArray(startAfter)) startAfter = startAfter[0]
    let prevToken = parsedUrl.query['continuation-token']
    if (Array.isArray(prevToken)) prevToken = prevToken[0]
    if (prevToken) {
      const tokenInfo = this.tokens.get(prevToken)
      this.tokens.delete(prevToken)

      if (!tokenInfo) throw new Error('invalid next token')
      offset = tokenInfo.offset

      if (tokenInfo.startAfter) {
        startAfter = tokenInfo.startAfter
      }
    }

    if (startAfter) {
      const index = rawObjects.findIndex((o) => {
        if (o.type === 's3-common-prefix') return
        return o.key === startAfter
      })
      if (index >= 0) {
        rawObjects = rawObjects.slice(index + 1)
      }
    }

    const end = offset + maxKeys
    const resultObjects = rawObjects.slice(offset, end)
    const truncated = rawObjects.length > end

    let nextToken: string | undefined;
    if (truncated) {
      nextToken = cuuid()
      this.tokens.set(nextToken, {
        offset: end,
        startAfter: startAfter
      })
    }

    return {
      objects: resultObjects,
      prevToken: prevToken,
      maxKeys: maxKeys,
      nextToken: nextToken
    }
  }

  splitObjects(objects: S3Object[], delimiter: string, prefix: string | undefined) {
    const prefixSet: Set<string> = new Set();
    const out: Array<S3Object | CommonPrefix> = [];
    for (const obj of objects) {
      const key = prefix ? obj.key.slice(prefix.length) : obj.key

      const parts = key.split(delimiter)
      if (parts.length === 1) {
        out.push(obj)
      } else {
        const segment = parts[0] + delimiter
        if (prefixSet.has(segment)) {
          continue
        } else {
          out.push(new CommonPrefix((prefix || '') + segment))
          prefixSet.add(segment)
        }
      }
    }
    return out
  }

  async _handleGetObjectsV2(req: http.IncomingMessage, parsedUrl: url.UrlWithParsedQuery) {
    const parts = decodeURIComponent(parsedUrl.pathname || '').split('/')
    if (parts.length > 3 || parts[0] || parts[2]) {
      throw new Error('invalid url, expected /:bucket')
    }

    const bucket = parts[1]
    const bucketsMap = this._getBucketsMap(req, parsedUrl);
    const s3bucket = bucketsMap ? bucketsMap.get(bucket) : null
    if (!s3bucket) {
      const err = new NoSuchBucketError(
        'The specified bucket does not exist', bucket
      )
      throw err
    }

    let objects = await s3bucket.getObjects();
    objects.sort((a, b) => {
      return a.key < b.key ? -1 : 1
    })

    let prefix = parsedUrl.query.prefix
    if (Array.isArray(prefix)) prefix = prefix[0]
    if (prefix) {
      const filterPrefix = prefix
      objects = objects.filter((o) => {
        return o.key.startsWith(filterPrefix)
      })
    }

    let delimiter = parsedUrl.query.delimiter;
    let allObjects: (S3Object | CommonPrefix)[];
    if (delimiter) {
      if (Array.isArray(delimiter)) delimiter = delimiter[0]
      allObjects = this.splitObjects(objects, delimiter, prefix)
    } else {
      allObjects = objects
    }

    const {
      prevToken, nextToken, maxKeys,
      objects: resultObjects
    } = this.paginate(parsedUrl, allObjects)

    let contentXml = ''
    let commonPrefixes = ''
    for (const o of resultObjects) {
      if (o.type === 's3-object') {
        contentXml += `<Contents>
          <Key>${escapeXML(o.key)}</Key>
          <LastModified>${escapeXML(o.lastModified)}</LastModified>
          <ETag>${escapeXML(o.md5)}</ETag>
          <Size>${o.contentLength}</Size>
          <StorageClass>STANDARD</StorageClass>
        </Contents>`
      } else {
        commonPrefixes += `<CommonPrefixes>
          <Prefix>${escapeXML(o.prefix)}</Prefix>
        </CommonPrefixes>`
      }
    }

    const truncated = Boolean(nextToken)
    const contToken = nextToken
      ? `<NextContinuationToken>${escapeXML(nextToken)}</NextContinuationToken>` : '';
    const prevContToken = prevToken ? `<ContinuationToken>${escapeXML(prevToken)}</ContinuationToken>` : '';
    const delimiterResp = delimiter ? `<Delimiter>${escapeXML(delimiter)}</Delimiter>` : '';

    return `<ListObjectsV2Output>
      <IsTruncated>${truncated}</IsTruncated>
      <Marker></Marker>
      <Name>${escapeXML(bucket)}</Name>
      <Prefix>${escapeXML(prefix || '')}</Prefix>
      <MaxKeys>${maxKeys}</MaxKeys>
      <KeyCount>${resultObjects.length}</KeyCount>
      <!-- TODO: support CommonPrefixes -->
      ${contentXml}
      ${commonPrefixes}
      ${contToken}
      ${prevContToken}
      ${delimiterResp}
    </ListObjectsV2Output>`
  }

  async _handleGetObject(req: http.IncomingMessage, res: http.ServerResponse, parsedUrl: url.UrlWithParsedQuery) {
    const parts = decodeURIComponent(parsedUrl.pathname || '').split('/');
    if (parts.length < 2 || parts[0]) {
      throw new Error('invalid url, expected /:bucket/:key')
    }

    const [, bucket, ...keyParts] = parts;

    const bucketsMap = this._getBucketsMap(req, parsedUrl);
    const s3bucket = bucketsMap ? bucketsMap.get(bucket) : null
    if (!s3bucket) {
      const err = new NoSuchBucketError(
        'The specified bucket does not exist', bucket
      )
      throw err
    }

    const filePath = s3bucket.getObjectPath(path.join(...keyParts));
    const exists = await existsP(filePath);

    if (exists) {
      if (req.headers['range']) {
        const range = req.headers.range;
        const rangeParts = range.replace(/bytes=/, "").split("-");
        const partialstart = rangeParts[0];
        const partialend = rangeParts[1];

        const start = parseInt(partialstart, 10);

        const stat = await statP(filePath);
        const total = stat.size;
        const end = partialend ? parseInt(partialend, 10) : total - 1;
        const chunksize = (end - start) + 1;

        const file = fs.createReadStream(filePath, { start: start, end: end });
        res.writeHead(206, { 'Content-Range': 'bytes ' + start + '-' + end + '/' + total, 'Accept-Ranges': 'bytes', 'Content-Length': chunksize });
        file.pipe(res);
      } else {
        res.writeHead(200, {
          "Content-Type": "application/octet-stream"
        });

        fs.createReadStream(filePath).pipe(res);
      }
      return;
    }

    res.writeHead(404, { "Content-Type": "text/plain" });
    res.end("ERROR File does not exist");
  }

  _buildError(err: unknown) {
    let resourceStr = ''
    let code: unknown = 'InternalError';
    let message: string = '';
    if (typeof err === 'object' && err) {
      if ("resource" in err && err.resource && typeof err.resource === 'string')
        resourceStr = `<Resource>${escapeXML(err.resource)}</Resource>`

      if ("code" in err && err.code)
        code = err.code;

      if ("message" in err && typeof err.message === 'string')
        message = err.message;
    }

    return `<Error>
      <Code>${code}</Code>
      <Message>${escapeXML(message)}</Message>
      ${resourceStr}
      <RequestId>1</RequestId>
    </Error>`
  }

  _writeError(err: unknown, res: http.ServerResponse) {
    const xml = this._buildError(err)
    res.writeHead(500, { 'Content-Type': 'text/xml' })
    res.end(xml)
  }

  async _handleServerRequest(req: http.IncomingMessage, res: http.ServerResponse) {
    const buffers: Buffer[] = [];
    req.on('data', (chunk: Buffer) => buffers.push(chunk));
    req.on('end', async () => {
      try {
        const bodyBuf = Buffer.concat(buffers);

        const reqUrl = req.url || ''
        const parsedUrl = url.parse(reqUrl, true);

        //console.log({ method: req.method, url: req.url, Headers: req.rawHeaders });

        res.setHeader('Access-Control-Allow-Methods', 'GET, PUT, DELETE');
        res.setHeader('Access-Control-Allow-Origin', '*');
        res.setHeader('Access-Control-Allow-Headers', '*');

        if (req.method === 'OPTIONS') {
          //That's fine
          res.end();
          return;
        }

        let signature: string | undefined;
        let accessKeyId: string | undefined;
        if (req.headers.authorization) {
          signature = req.headers.authorization.match(/Signature=(.+)$/)?.[1];
          accessKeyId = req.headers.authorization.match(/Credential=([^/]+)/)?.[1];
        } else {
          const credQuery = parsedUrl.query["X-Amz-Credential"];
          accessKeyId = Array.isArray(credQuery) ? credQuery[0] : credQuery;
          accessKeyId = accessKeyId?.match(/^([^/]+)/)?.[1];

          const signQuery = parsedUrl.query["X-Amz-Signature"];
          signature = Array.isArray(signQuery) ? signQuery[0] : signQuery;
        }

        if (!accessKeyId || !signature) {
          res.writeHead(403, { "Content-Type": "text/plain" });
          res.end("403 Forbidden");
          return;
        }

        const profile = this._profiles.get(accessKeyId);
        if (!profile) {
          res.writeHead(403, { "Content-Type": "text/plain" });
          res.end("403 Forbidden");
          return;
        }

        const signer = new RequestSigner(req, bodyBuf, "s3", "us-west-2", { accessKeyId, secretAccessKey: profile.secretAccessKey });

        if (signer.signature() !== signature || signer.isExpired(12 * 60 * 60)) {
          console.log({ method: req.method, url: req.url, Headers: req.rawHeaders });

          console.log(signer.stringToSign(), signer.canonicalString(), signer.signature());

          res.writeHead(403, { "Content-Type": "text/plain" });
          res.end("403 Forbidden");
          return;
        }

        if (req.method === 'PUT') {
          let obj: S3Object | undefined;
          try {
            obj = await this._handlePutObject(req, bodyBuf, parsedUrl);
          } catch (err) {
            return this._writeError(err, res)
          }

          res.setHeader('ETag', JSON.stringify(obj.md5))
          res.end()
        } else if (req.method === 'GET' && req.url === '/') {
          let xml: string | undefined;
          try {
            xml = this._handleListBuckets(req, parsedUrl);
          } catch (err) {
            return this._writeError(err, res)
          }

          res.writeHead(200, { 'Content-Type': 'text/xml' })
          res.end(xml)
        } else if (req.method === 'GET' && parsedUrl.query["x-id"] === "GetObject") {
          try {
            await this._handleGetObject(req, res, parsedUrl);
          } catch (err) {
            console.error(err);
            return this._writeError(err, res)
          }
        } else if (req.method === 'GET') {
          let xml: string | undefined;
          try {
            xml = await this._handleGetObjectsV2(req, parsedUrl);
          } catch (err) {
            console.error(err);
            return this._writeError(err, res)
          }

          res.writeHead(200, { 'Content-Type': 'text/xml' })
          res.end(xml)
        } else {
          this._writeError(new Error(
            `url not supported: ${req.method} ${req.url}`
          ), res)
        }
      } catch (err) {
        console.error(err);
      }
    })
  }
}

function escapeXML(str: unknown) {
  return str?.toString()
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/'/g, '&apos;')
    .replace(/"/g, '&quot;')
}

function cuuid() {
  const str = (
    Date.now().toString(16) +
    Math.random().toString(16).slice(2) +
    Math.random().toString(16).slice(2)
  ).slice(0, 32)
  return str.slice(0, 8) + '-' + str.slice(8, 12) + '-' +
    str.slice(12, 16) + '-' + str.slice(16, 20) + '-' +
    str.slice(20)
}

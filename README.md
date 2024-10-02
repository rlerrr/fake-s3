# fake-s3

A fake s3 server for testing purposes.

This is a zero dependency implementation that stores all objects on the filesystem

## Example

```js
import FakeS3 from 'fake-s3';
import * as S3 from "@aws-sdk/client-s3";

const server = new FakeS3({
  port: 8080,
  users: [{
    accessKeyId: 'testKey',
    secretAccessKey: 'superSecret',
    buckets: [{
      name: 'my-bucket',
      path: '/path/to/bucket/files'
    }]
  }]
})

// Start the server on specified port
await server.bootstrap();

// Create an S3 client connected to it
const s3 = new S3.S3Client({
  endpoint: `http://${server.hostPort}`
  sslEnabled: false,
  s3ForcePathStyle: true,
  credentials: {    
    accessKeyId: 'testKey',
    secretAccessKey: 'superSecret'
  }
});
```

## Support

The following `aws-sdk` methods are supported

 - `s3.listBuckets()`
 - `s3.listObjectsV2()`
 - `s3.getObject()`
 - `s3.upload()`
 - `s3-request-presigner -> getSignedUrl()`

## Features

Get/List/Put objects to/from the filesystem

Signature verification on regular calls and presigned URLs

Optional crude form of "versioning" to avoid accidental file destruction

## Docs

### `new FakeS3(options)`
 - `options.port` : the port to bind to.  Will default to a random port if unspecified.
 - `options.users` : an array of users which may access the server, and their associated buckets.

### `server.hostPort`

This is the `hostPort` that the server is listening on, this
will be non-null after `bootstrap()` finishes.

### `await server.bootstrap()`

starts the server

### `await server.close()`

closes the HTTP server.

## Installation

`npm install fake-s3`

## Tests

`npm test`

## Contributors

 - Raynos

## MIT Licensed

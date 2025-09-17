const express = require('express');
const app = express();
const path = require('path');
const htmlparser = require('node-html-parser');
const { existsSync, mkdirSync, readFileSync, writeFileSync } = require('fs');
const fs = require('fs/promises')
const crypto = require('crypto')

/**
 * @typedef {object} MerkleTree
 * @property {string} root
 * @property {string[]} leaves
 * @property {string[]} files
 */

/**
 * Calculates the SHA256 hash of a string.
 * @param {string} data The string to hash.
 * @returns {string} The hex-encoded hash.
 */
function sha256(data) {
    return crypto.createHash('sha256').update(data).digest('hex');
}

// Simple Merkle Tree Implementation
/** @type {MerkleTree | null} */
let merkleTree = null;
/** @type {string[]} */
let fileList = [];
/** @type {Object.<string, [string, string]>} */
const nodes = {};

/**
 * Builds the Merkle tree from the files in the save directory.
 * @returns {Promise<void>}
 */
async function buildMerkleTree() {
    console.log('[Merkle] Building tree...');
    Object.keys(nodes).forEach(key => delete nodes[key]);
    const files = await fs.readdir(path.join(savePath));
    const newFileList = files.map((v) => Buffer.from(v, 'hex').toString('utf-8')).sort();

    const leaves = newFileList.map(sha256);

    if (leaves.length === 0) {
        merkleTree = null;
        fileList = [];
        return;
    }

    /**
     * Recursively builds the Merkle tree.
     * @param {string[]} leaves The leaves to build the tree from.
     * @returns {string} The root of the tree.
     */
    const build = (leaves) => {
        if (leaves.length === 1) return leaves[0];
        const parents = [];
        for (let i = 0; i < leaves.length; i += 2) {
            const left = leaves[i];
            const right = (i + 1 < leaves.length) ? leaves[i + 1] : left;
            const parent = sha256(left + right);
            nodes[parent] = [left, right];
            parents.push(parent);
        }
        return build(parents);
    };
    const root = build(leaves);

    merkleTree = { root, leaves, files: newFileList };
    fileList = newFileList;
    console.log('[Merkle] Tree built successfully. Root:', merkleTree ? merkleTree.root : null);
}

app.use(express.static(path.join(process.cwd(), 'dist'), {index: false}));
app.use(express.json({ limit: '100mb' }));
app.use(express.raw({ type: 'application/octet-stream', limit: '100mb' }));
app.use(express.text({ limit: '100mb' }));
const {pipeline} = require('stream/promises')
const https = require('https');
const sslPath = path.join(process.cwd(), 'server/node/ssl/certificate');
const hubURL = 'https://sv.risuai.xyz'; 

let password = ''

const savePath = path.join(process.cwd(), "save")
if(!existsSync(savePath)){
    mkdirSync(savePath)
}

const passwordPath = path.join(process.cwd(), 'save', '__password')
if(existsSync(passwordPath)){
    password = readFileSync(passwordPath, 'utf-8')
}
const hexRegex = /^[0-9a-fA-F]+$/;
/**
 * Checks if a string is a valid hex string.
 * @param {string} str The string to check.
 * @returns {boolean}
 */
function isHex(str) {
    return hexRegex.test(str.toUpperCase().trim()) || str === '__password';
}

/**
 * @param {express.Request} req
 * @param {express.Response} res
 * @param {express.NextFunction} next
 */
app.get('/', async (req, res, next) => {

    const clientIP = req.headers['x-forwarded-for'] || req.ip || req.socket.remoteAddress || 'Unknown IP';
    const timestamp = new Date().toISOString();
    console.log(`[Server] ${timestamp} | Connection from: ${clientIP}`);
    
    try {
        const mainIndex = await fs.readFile(path.join(process.cwd(), 'dist', 'index.html'))
        const root = htmlparser.parse(mainIndex.toString())
        const head = root.querySelector('head')
        head.innerHTML = `<script>globalThis.__NODE__ = true</script>` + head.innerHTML
        
        res.send(root.toString())
    } catch (error) {
        console.log(error)
        next(error)
    }
})

/**
 * @param {express.Request} req
 * @param {express.Response} res
 * @param {express.NextFunction} next
 */
const reverseProxyFunc = async (req, res, next) => {
    const authHeader = req.headers['risu-auth'] || '';
    if(authHeader.trim() !== password.trim()){
        console.log('incorrect', 'received:', authHeader, 'expected:', password)
        res.status(400).send({
            error:'Password Incorrect'
        });
        return
    }
    
    const urlParam = req.headers['risu-url'] ? decodeURIComponent(/** @type {string} */ (req.headers['risu-url'])) : req.query.url;

    if (!urlParam) {
        res.status(400).send({
            error:'URL has no param'
        });
        return;
    }
    const header = req.headers['risu-header'] ? JSON.parse(decodeURIComponent(/** @type {string} */ (req.headers['risu-header']))) : req.headers;
    if(!header['x-forwarded-for']){
        header['x-forwarded-for'] = req.ip
    }
    let originalResponse;
    try {
        // make request to original server
        originalResponse = await fetch(/** @type {string} */ (urlParam), {
            method: req.method,
            headers: header,
            body: JSON.stringify(req.body)
        });
        // get response body as stream
        const originalBody = originalResponse.body;
        // get response headers
        const head = new Headers(originalResponse.headers);
        head.delete('content-security-policy');
        head.delete('content-security-policy-report-only');
        head.delete('clear-site-data');
        head.delete('Cache-Control');
        head.delete('Content-Encoding');
        const headObj = {};
        for (let [k, v] of head) {
            headObj[k] = v;
        }
        // send response headers to client
        res.header(headObj);
        // send response status to client
        res.status(originalResponse.status);
        // send response body to client
        await pipeline(/** @type {NodeJS.ReadableStream} */ (originalBody), res);


    }
    catch (err) {
        next(err);
        return;
    }
}

/**
 * @param {express.Request} req
 * @param {express.Response} res
 * @param {express.NextFunction} next
 */
const reverseProxyFunc_get = async (req, res, next) => {
    const authHeader = req.headers['risu-auth'] || '';
    if(authHeader.trim() !== password.trim()){
        console.log('incorrect', 'received:', authHeader, 'expected:', password)
        res.status(400).send({
            error:'Password Incorrect'
        });
        return
    }
    
    const urlParam = req.headers['risu-url'] ? decodeURIComponent(/** @type {string} */ (req.headers['risu-url'])) : req.query.url;

    if (!urlParam) {
        res.status(400).send({
            error:'URL has no param'
        });
        return;
    }
    const header = req.headers['risu-header'] ? JSON.parse(decodeURIComponent(/** @type {string} */ (req.headers['risu-header']))) : req.headers;
    if(!header['x-forwarded-for']){
        header['x-forwarded-for'] = req.ip
    }
    let originalResponse;
    try {
        // make request to original server
        originalResponse = await fetch(/** @type {string} */(urlParam), {
            method: 'GET',
            headers: header
        });
        // get response body as stream
        const originalBody = originalResponse.body;
        // get response headers
        const head = new Headers(originalResponse.headers);
        head.delete('content-security-policy');
        head.delete('content-security-policy-report-only');
        head.delete('clear-site-data');
        head.delete('Cache-Control');
        head.delete('Content-Encoding');
        const headObj = {};
        for (let [k, v] of head) {
            headObj[k] = v;
        }
        // send response headers to client
        res.header(headObj);
        // send response status to client
        res.status(originalResponse.status);
        // send response body to client
        await pipeline(/** @type {NodeJS.ReadableStream} */ (originalBody), res);
    }
    catch (err) {
        next(err);
        return;
    }
}

/**
 * @param {express.Request} req
 * @param {express.Response} res
 */
async function hubProxyFunc(req, res) {
    const excludedHeaders = [
        'content-encoding',
        'content-length',
        'transfer-encoding'
    ];

    try {
        const pathAndQuery = req.originalUrl.replace(/^\/hub-proxy/, '');
        const externalURL = hubURL + pathAndQuery;
        
        const headersToSend = { ...req.headers };
        delete headersToSend.host;
        delete headersToSend.connection;
        delete headersToSend['content-length'];
        
        const hubOrigin = new URL(hubURL).origin;
        headersToSend.origin = hubOrigin;
        
        const response = await fetch(externalURL, {
            method: req.method,
            headers: headersToSend,
            body: req.method !== 'GET' && req.method !== 'HEAD' ? req.body : undefined,
            redirect: 'manual',
            // @ts-ignore
            duplex: 'half'
        });
        
        for (const [key, value] of response.headers.entries()) {
            // Skip encoding-related headers to prevent double decoding
            if (excludedHeaders.includes(key.toLowerCase())) {
                continue;
            }
            res.setHeader(key, value);
        }
        res.status(response.status);
        
        if (response.status >= 300 && response.status < 400 && response.headers.get('location')) {
            const redirectUrl = response.headers.get('location');
            const newHeaders = { ...headersToSend };
            const redirectResponse = await fetch(redirectUrl, {
                method: req.method,
                headers: newHeaders,
                body: req.method !== 'GET' && req.method !== 'HEAD' ? req.body : undefined,
                redirect: 'manual',
                // @ts-ignore
                duplex: 'half'
            });
            for (const [key, value] of redirectResponse.headers.entries()) {
                if (excludedHeaders.includes(key.toLowerCase())) {
                    continue;
                }
                res.setHeader(key, value);
            }
            res.status(redirectResponse.status);
            await pipeline(/** @type {NodeJS.ReadableStream} */ (redirectResponse.body), res);
            return;
        }
        
        await pipeline(/** @type {NodeJS.ReadableStream} */ (response.body), res);
        
    } catch (error) {
        console.error("[Hub Proxy] Error:", error);
        if (!res.headersSent) {
            res.status(502).send({ error: 'Proxy request failed: ' + error.message });
        } else {
            res.end();
        }
    }
}

app.get('/proxy', reverseProxyFunc_get);
app.get('/proxy2', reverseProxyFunc_get);
app.get('/hub-proxy/*', hubProxyFunc);

app.post('/proxy', reverseProxyFunc);
app.post('/proxy2', reverseProxyFunc);
app.post('/hub-proxy/*', hubProxyFunc);

/**
 * @param {express.Request} req
 * @param {express.Response} res
 */
app.get('/api/password', async(req, res)=> {
    if(password === ''){
        res.send({status: 'unset'})
    }
    else if(req.headers['risu-auth']  === password){
        res.send({status:'correct'})
    }
    else{
        res.send({status:'incorrect'})
    }
})

/**
 * @param {express.Request} req
 * @param {express.Response} res
 * @param {express.NextFunction} next
 */
app.post('/api/crypto', async (req, res, next) => {
    try {
        const hash = crypto.createHash('sha256')
        hash.update(Buffer.from(req.body.data, 'utf-8'))
        res.send(hash.digest('hex'))
    } catch (error) {
        next(error)
    }
})

/**
 * @param {express.Request} req
 * @param {express.Response} res
 */
app.post('/api/set_password', async (req, res) => {
    if(password === ''){
        password = req.body.password
        writeFileSync(passwordPath, password, 'utf-8')
    }
    res.status(400).send("already set")
})

/**
 * @param {express.Request} req
 * @param {express.Response} res
 * @param {express.NextFunction} next
 */
app.get('/api/read', async (req, res, next) => {
    if((req.headers['risu-auth'] || '').trim() !== password.trim()){
        console.log('incorrect')
        res.status(400).send({
            error:'Password Incorrect'
        });
        return
    }
    const filePath = req.headers['file-path'];
    if (!filePath || typeof filePath !== 'string') {
        console.log('no path')
        res.status(400).send({
            error:'File path required'
        });
        return;
    }

    if(!isHex(filePath)){
        res.status(400).send({
            error:'Invaild Path'
        });
        return;
    }
    try {
        if(!existsSync(path.join(savePath, filePath))){
            res.send();
        }
        else{
            res.setHeader('Content-Type','application/octet-stream');
            res.sendFile(path.join(savePath, filePath));
        }
    } catch (error) {
        next(error);
    }
});

/**
 * @param {express.Request} req
 * @param {express.Response} res
 * @param {express.NextFunction} next
 */
app.get('/api/remove', async (req, res, next) => {
    if((req.headers['risu-auth'] || '').trim() !== password.trim()){
        console.log('incorrect')
        res.status(400).send({
            error:'Password Incorrect'
        });
        return
    }
    const filePath = req.headers['file-path'];
    if (!filePath || typeof filePath !== 'string') {
        res.status(400).send({
            error:'File path required'
        });
        return;
    }
    if(!isHex(filePath)){
        res.status(400).send({
            error:'Invaild Path'
        });
        return;
    }

    try {
        await fs.rm(path.join(savePath, filePath));
        await buildMerkleTree();
        res.send({
            success: true,
        });
    } catch (error) {
        next(error);
    }
});

/**
 * @param {express.Request} req
 * @param {express.Response} res
 * @param {express.NextFunction} next
 */
app.get('/api/merkle/root', async (req, res, next) => {
    if((req.headers['risu-auth'] || '').trim() !== password.trim()){
        res.status(400).send({ error:'Password Incorrect' });
        return;
    }
    try {
        if (!merkleTree) {
            res.send({ root: null, files: [] });
            return;
        }
        res.send({ root: merkleTree.root, files: merkleTree.files });
    } catch (error) {
        next(error);
    }
});

/**
 * @param {express.Request} req
 * @param {express.Response} res
 * @param {express.NextFunction} next
 */
app.get('/api/merkle/node/:hash', async (req, res, next) => {
    if((req.headers['risu-auth'] || '').trim() !== password.trim()){
        res.status(400).send({ error:'Password Incorrect' });
        return;
    }
    const { hash } = req.params;
    if (nodes[hash]) {
        res.send(nodes[hash]);
    } else {
        res.status(404).send({ error: 'Node not found' });
    }
});

/**
 * @param {express.Request} req
 * @param {express.Response} res
 * @param {express.NextFunction} next
 */
app.get('/api/list', async (req, res, next) => {
    if((req.headers['risu-auth'] || '').trim() !== password.trim()){
        console.log('incorrect')
        res.status(400).send({
            error:'Password Incorrect'
        });
        return
    }
    try {
        const data = (await fs.readdir(path.join(savePath))).map((v) => {
            return Buffer.from(v, 'hex').toString('utf-8')
        })
        res.send({
            success: true,
            content: data
        });
    } catch (error) {
        next(error);
    }
});

/**
 * @param {express.Request} req
 * @param {express.Response} res
 * @param {express.NextFunction} next
 */
app.post('/api/write', async (req, res, next) => {
    if((req.headers['risu-auth'] || '').trim() !== password.trim()){
        console.log('incorrect')
        res.status(400).send({
            error:'Password Incorrect'
        });
        return
    }
    const filePath = req.headers['file-path'];
    const fileContent = req.body
    if (!filePath || typeof filePath !== 'string' || !fileContent) {
        res.status(400).send({
            error:'File path and content are required'
        });
        return;
    }
    if(!isHex(filePath)){
        res.status(400).send({
            error:'Invaild Path'
        });
        return;
    }

    try {
        await fs.writeFile(path.join(savePath, filePath), fileContent);
        await buildMerkleTree();
        res.send({
            success: true
        });
    } catch (error) {
        next(error);
    }
});

/**
 * @returns {Promise<{key: Buffer, cert: Buffer} | null>}
 */
async function getHttpsOptions() {

    const keyPath = path.join(sslPath, 'server.key');
    const certPath = path.join(sslPath, 'server.crt');

    try {
 
        await fs.access(keyPath);
        await fs.access(certPath);

        const [key, cert] = await Promise.all([
            fs.readFile(keyPath),
            fs.readFile(certPath)
        ]);
       
        return { key, cert };

    } catch (error) {
        console.error('[Server] SSL setup errors:', error.message);
        console.log('[Server] Start the server with HTTP instead of HTTPS...');
        return null;
    }
}

/**
 * @returns {Promise<void>}
 */
async function startServer() {
    try {
      
        const port = process.env.PORT || 6001;
        const httpsOptions = await getHttpsOptions();

        if (httpsOptions) {
            // HTTPS
            https.createServer(httpsOptions, app).listen(port, () => {
                console.log("[Server] HTTPS server is running.");
                console.log(`[Server] https://localhost:${port}/`);
            });
        } else {
            // HTTP
            app.listen(port, () => {
                console.log("[Server] HTTP server is running.");
                console.log(`[Server] http://localhost:${port}/`);
            });
        }
    } catch (error) {
        console.error('[Server] Failed to start server :', error);
        process.exit(1);
    }
}

(async () => {
    await buildMerkleTree();
    await startServer();
})();

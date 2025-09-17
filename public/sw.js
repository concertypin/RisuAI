// @ts-nocheck

/**
 * Verification Mode Flag
 * Set to true to run the original /api/list request in parallel and compare the results.
 * This is for testing and debugging purposes.
 */
const VERIFICATION_MODE = true;

const CACHE_NAME = 'risuCache';
const MERKLE_ROOT_KEY = 'merkle-root';
const FILE_LIST_KEY = 'file-list';
const NODE_KEY_PREFIX = 'merkle-node-';
const LEAF_TO_FILE_KEY_PREFIX = 'merkle-leaf-';

/**
 * Fetches a URL with an authorization header if present.
 * @param {string | Request} url The URL to fetch.
 * @param {Headers} [headers] The headers from the original request.
 * @returns {Promise<Response>}
 */
async function fetchWithAuth(url, headers) {
    const auth = headers ? headers.get('risu-auth') : undefined;
    const newHeaders = new Headers();
    if (auth) newHeaders.set('risu-auth', auth);
    return fetch(url, { headers: newHeaders });
}

/**
 * Calculates the SHA256 hash of a string.
 * @param {string} str The string to hash.
 * @returns {Promise<string>} The hex-encoded hash.
 */
async function sha256(str) {
    const buffer = new TextEncoder().encode(str);
    const hash = await crypto.subtle.digest('SHA-256', buffer);
    return Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Synchronizes the file list with the server using a Merkle tree.
 * @param {Request} request The incoming request.
 * @returns {Promise<Response>}
 */
async function synchronizeFiles(request) {
    const cache = await caches.open(CACHE_NAME);
    const localRootRes = await cache.match(MERKLE_ROOT_KEY);
    const localRoot = localRootRes ? await localRootRes.text() : null;

    const serverRes = await fetchWithAuth('/api/merkle/root', request.headers).catch(() => null);

    if (!serverRes || !serverRes.ok) {
        const cachedList = await cache.match(FILE_LIST_KEY);
        if (cachedList) return cachedList;
        return new Response(JSON.stringify({ success: false, content: [] }), { status: 500 });
    }

    const { root: serverRoot, files: serverFiles } = await serverRes.json();

    if (localRoot === serverRoot) {
        const fileListRes = await cache.match(FILE_LIST_KEY);
        if (fileListRes) return fileListRes;
    }

    const allServerLeaves = await Promise.all(serverFiles.map(/** @param {string} file */ file => sha256(file)));
    for (let i = 0; i < allServerLeaves.length; i++) {
        await cache.put(new Request(LEAF_TO_FILE_KEY_PREFIX + allServerLeaves[i]), new Response(serverFiles[i]));
    }

    const activeCacheKeys = new Set([
        new Request(MERKLE_ROOT_KEY).url,
        new Request(FILE_LIST_KEY).url,
    ]);

    const fileList = await diffAndBuildFileList(localRoot, serverRoot, request.headers, cache, activeCacheKeys);

    await cache.put(new Request(MERKLE_ROOT_KEY), new Response(serverRoot || ''));
    await cache.put(new Request(FILE_LIST_KEY), new Response(JSON.stringify(fileList), { headers: { 'Content-Type': 'application/json' } }));

    const keys = await cache.keys();
    for (const key of keys) {
        const urlStr = key.url;
        if (urlStr.includes(NODE_KEY_PREFIX) || urlStr.includes(LEAF_TO_FILE_KEY_PREFIX)) {
            if (!activeCacheKeys.has(urlStr)) {
                 await cache.delete(key);
            }
        }
    }

    return new Response(JSON.stringify({ success: true, content: fileList }), { headers: { 'Content-Type': 'application/json' } });
}

/**
 * Recursively compares the local and remote Merkle trees to build the list of current files.
 * @param {string | null} localHash The hash of the local node.
 * @param {string | null} remoteHash The hash of the remote node.
 * @param {Headers} headers The request headers for fetching nodes.
 * @param {Cache} cache The cache storage.
 * @param {Set<string>} activeCacheKeys A set to track active cache keys for cleanup.
 * @returns {Promise<string[]>} A promise that resolves to the list of file paths.
 */
async function diffAndBuildFileList(localHash, remoteHash, headers, cache, activeCacheKeys) {
    if (!remoteHash) return [];

    activeCacheKeys.add(new Request(NODE_KEY_PREFIX + remoteHash).url);
    activeCacheKeys.add(new Request(LEAF_TO_FILE_KEY_PREFIX + remoteHash).url);

    if (localHash === remoteHash) {
        return await collectFilesFromCache(remoteHash, cache, activeCacheKeys);
    }

    const remoteChildren = await fetchWithAuth(`/api/merkle/node/${remoteHash}`, headers).then(res => res.ok ? res.json() : null).catch(() => null);

    if (!remoteChildren) {
        const fileRes = await cache.match(LEAF_TO_FILE_KEY_PREFIX + remoteHash);
        if (fileRes) {
            return [await fileRes.text()];
        }
        return [];
    }

    await cache.put(new Request(NODE_KEY_PREFIX + remoteHash), new Response(JSON.stringify(remoteChildren)));

    const localChildren = await cache.match(NODE_KEY_PREFIX + localHash).then(res => res ? res.json() : null).catch(() => [null, null]);

    const leftFiles = await diffAndBuildFileList(localChildren[0], remoteChildren[0], headers, cache, activeCacheKeys);
    let rightFiles = [];
    if (remoteChildren[0] !== remoteChildren[1]) {
        rightFiles = await diffAndBuildFileList(localChildren[1], remoteChildren[1], headers, cache, activeCacheKeys);
    }

    return [...leftFiles, ...rightFiles];
}

/**
 * Recursively collects all file paths under a given node hash from the cache.
 * @param {string | null} hash The hash of the node to start from.
 * @param {Cache} cache The cache storage.
 * @param {Set<string>} activeCacheKeys A set to track active cache keys for cleanup.
 * @returns {Promise<string[]>} A promise that resolves to the list of file paths.
 */
async function collectFilesFromCache(hash, cache, activeCacheKeys) {
    if (!hash) return [];

    activeCacheKeys.add(new Request(NODE_KEY_PREFIX + hash).url);
    activeCacheKeys.add(new Request(LEAF_TO_FILE_KEY_PREFIX + hash).url);

    const children = await cache.match(NODE_KEY_PREFIX + hash).then(res => res ? res.json() : null);

    if (children) {
        const leftFiles = await collectFilesFromCache(children[0], cache, activeCacheKeys);
        let rightFiles = [];
        if (children[0] !== children[1]) {
            rightFiles = await collectFilesFromCache(children[1], cache, activeCacheKeys);
        }
        return [...leftFiles, ...rightFiles];
    } else {
        const fileRes = await cache.match(LEAF_TO_FILE_KEY_PREFIX + hash);
        if (fileRes) {
            return [await fileRes.text()];
        }
        return [];
    }
}

/**
 * Compares two arrays of strings for equality, ignoring order.
 * @param {string[]} arr1
 * @param {string[]} arr2
 * @returns {boolean}
 */
function compareFileLists(arr1, arr2) {
    if (arr1.length !== arr2.length) return false;
    const sorted1 = [...arr1].sort();
    const sorted2 = [...arr2].sort();
    return sorted1.every((value, index) => value === sorted2[index]);
}

/**
 * In verification mode, this function fetches the original list and compares it with the list from the Merkle sync.
 * @param {Promise<Response>} merkleResponsePromise A promise that resolves to the response from the Merkle sync logic.
 * @param {Request} originalRequest The original request object.
 */
async function verifySync(merkleResponsePromise, originalRequest) {
    console.log('[VERIFY] Running verification...');
    try {
        const merkleResponse = await merkleResponsePromise;
        const merkleData = await merkleResponse.clone().json();
        const merkleFileList = merkleData.content;

        const verificationUrl = new URL(originalRequest.url);
        verificationUrl.searchParams.set('verify', 'true');
        const verificationRequest = new Request(verificationUrl, originalRequest);

        const originalResponse = await fetch(verificationRequest);
        const originalData = await originalResponse.json();
        const originalFileList = originalData.content;

        if (compareFileLists(merkleFileList, originalFileList)) {
            console.log('%c[VERIFY] SUCCESS: Merkle tree sync result matches original request.', 'color: green; font-weight: bold;');
        } else {
            console.error('[VERIFY] FAILURE: Mismatch between Merkle tree sync and original request.');
            console.log('[VERIFY] Merkle List:', merkleFileList);
            console.log('[VERIFY] Original List:', originalFileList);
        }
    } catch (err) {
        console.error('[VERIFY] Error during verification:', err);
    }
}

/**
 * @param {FetchEvent} event
 */
self.addEventListener('fetch', (event) => {
    const url = new URL(event.request.url);

    if (url.pathname === '/api/list') {
        if (url.searchParams.has('verify')) {
            event.respondWith(fetch(event.request));
            return;
        }

        const responsePromise = synchronizeFiles(event.request);
        event.respondWith(responsePromise);

        if (VERIFICATION_MODE) {
            event.waitUntil(verifySync(responsePromise, event.request));
        }
        return;
    }

    const path = url.pathname.split('/');
    if (path[1] === 'sw') {
        try {
            switch (path[2]) {
                case "check": {
                    let targetUrl = url;
                    const headers = event.request.headers;
                    const headerUrl = headers.get('x-register-url');
                    if (headerUrl) {
                        targetUrl.pathname = decodeURIComponent(headerUrl);
                    }
                    event.respondWith(checkCache(targetUrl));
                    break;
                }
                case "img": {
                    event.respondWith(getSource(url));
                    break;
                }
                case "register": {
                    let targetUrl = url;
                    const headers = event.request.headers;
                    const headerUrl = headers.get('x-register-url');
                    if (headerUrl) {
                        targetUrl.pathname = decodeURIComponent(headerUrl);
                    }
                    const noContentType = headers.get('x-no-content-type') === 'true';
                    event.respondWith(
                        registerCache(targetUrl, event.request.arrayBuffer(), noContentType)
                    );
                    break;
                }
                case "init": {
                    event.respondWith(new Response("v2"));
                    break;
                }
                case 'share': {
                    event.respondWith((async () => {
                        const formData = await event.request.formData();
                        const character = formData.get('character');
                        const preset = formData.get('preset');
                        const module = formData.get('module');
                        if (character instanceof File) {
                            const buf = await character.arrayBuffer();
                            await registerCache(new URL('/sw/share/character', self.location.origin), buf, true);
                            return Response.redirect("/#share_character", 303);
                        }
                        if (preset instanceof File) {
                            const buf = await preset.arrayBuffer();
                            await registerCache(new URL('/sw/share/preset', self.location.origin), buf, true);
                            return Response.redirect("/#share_preset", 303);
                        }
                        if (module instanceof File) {
                            const buf = await module.arrayBuffer();
                            await registerCache(new URL('/sw/share/module', self.location.origin), buf, true);
                            return Response.redirect("/#share_module", 303);
                        }
                        return Response.redirect("/", 303);
                    })());
                    break;
                }
                default: {
                    event.respondWith(new Response(
                        path[2]
                    ));
                }
            }
        } catch (error) {
            event.respondWith(new Response(`${error}`));
        }
    }
    if (path[1] === 'tf') {
        {
            event.respondWith(new Response("Cannot find resource from cache", {
                status: 404
            }));
        }
    }
});

/**
 * @param {URL} url
 * @returns {Promise<Response>}
 */
async function checkCache(url) {
    const cache = await caches.open('risuCache');

    if (url.pathname.startsWith("/sw/check")) {
        url.pathname = "/sw/img" + url.pathname.slice(9);
        return new Response(JSON.stringify({
            "able": !!(await cache.match(url))
        }));
    }

    return new Response(JSON.stringify({
        "able": !!(await cache.match(url))
    }));
}

/**
 * @param {URL} url
 * @returns {Promise<Response | undefined>}
 */
async function getSource(url) {
    const cache = await caches.open('risuCache');
    return await cache.match(url);
}

/**
 * @param {URL} urlr
 * @param {Promise<ArrayBuffer>} buffer
 * @param {boolean} [noContentType=false]
 * @returns {Promise<Response>}
 */
async function registerCache(urlr, buffer, noContentType = false) {
    const cache = await caches.open('risuCache');
    const url = new URL(urlr);
    if (!noContentType) {
        let path = url.pathname.split('/');
        path[2] = 'img';
        url.pathname = path.join('/');
    }
    const buf = new Uint8Array(await buffer);
    let headers = {
        "cache-control": "max-age=604800",
        "content-type": "image/png"
    };
    if (noContentType) {
        delete headers["content-type"];
    }
    await cache.put(url, new Response(buf, {
        headers
    }));
    return new Response(JSON.stringify({
        "done": true
    }));
}
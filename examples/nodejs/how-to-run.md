# How to Run

Follow the steps below to set up and run the project:

1. Install `node-gyp` globally. This is a cross-platform command-line tool written in Node.js for compiling native addon
   modules for Node.js. It bundles the gyp project used by the Chromium team and takes away the pain of dealing with the
   various differences in build platforms.

```bash
npm install -g node-gyp
```

2. Clone the `node-ffi-napi` repository. This is a Node.js addon for loading and calling dynamic libraries using pure
   JavaScript. It can be used to create bindings to native libraries without writing any C++ code.

```bash
git clone https://github.com/node-ffi-napi/node-ffi-napi.git ffi-napi
```

3. Navigate to the `ffi-napi` directory.

```bash
cd ffi-napi
```

4. Rebuild the project using `node-gyp`. This will compile the addon and produce a binary that can be loaded by Node.js.

```bash
node-gyp rebuild
```

5. Move the `ffi-napi` directory to `node_modules`. This will allow Node.js to find the addon when you require it in
   your code.

```bash
mkdir node_modules
mv ffi-napi ./node_modules/ffi-napi
```

Now, you should be able to require `ffi-napi` in your Node.js code and use it to load and call functions from dynamic
libraries.

6. run mnemonic.js

```bash
node mnemonic.js
```

7. run btc.js

```bash
node btc.js
```

8. run eth.js

```bash
node eth.js
```

9. run trx.js

```bash
node trx.js
```

const {spawnSync} = require('node:child_process');
const path = require('node:path');
const result = spawnSync('python3', [path.join(__dirname, 'raw_upload.py')], {stdio: 'inherit', env: process.env});
process.exit(result.status === null ? 1 : result.status);

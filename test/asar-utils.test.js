import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { execFileSync, spawnSync } from 'node:child_process';
import * as asar from '@electron/asar';
import {
    computeAsarHeaderHash,
    countUnpackedFiles,
    createPackOptionsFromHeader,
    getBackupPath,
    getMacInfoPlistPath,
    getUnpackedLayout,
    listUnpackedFiles,
    readArchiveManifest,
    resolveArchiveEntryPoint
} from '../bin/asar-utils.js';
import {
    ASAR_INTEGRITY_SENTINEL,
    computeIntegrityDictionaryDigest,
    ensureMacBundleBackup,
    findIntegritySlot,
    findMacFramework,
    hasOfficialSignature,
    patchMacFrameworkIntegrity,
    restoreMacBundleBackup,
    signMacAppBundle
} from '../bin/macos-signing.js';

function temporaryDirectory(t) {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'codex-rtl-test-'));
    t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
    return directory;
}

test('resolves the manifest-defined entry point and rejects traversal', t => {
    const root = temporaryDirectory(t);
    const buildDir = path.join(root, '.vite', 'build');
    fs.mkdirSync(buildDir, { recursive: true });
    const entryPath = path.join(buildDir, 'early-bootstrap.js');
    fs.writeFileSync(entryPath, 'require("./bootstrap-hash.js");');

    assert.equal(
        resolveArchiveEntryPoint(root, { main: '.vite/build/early-bootstrap.js' }),
        entryPath
    );
    assert.throws(
        () => resolveArchiveEntryPoint(root, { main: '../outside.js' }),
        /Unsafe ASAR main entry point/
    );
});

test('collapses fully unpacked trees without swallowing packed siblings', () => {
    const header = {
        files: {
            native: {
                files: {
                    'addon.node': { unpacked: true, size: 1 },
                    helper: { files: { tool: { unpacked: true, size: 1 } } }
                }
            },
            mixed: {
                files: {
                    'package.json': { size: 1 },
                    build: { files: { 'addon.node': { unpacked: true, size: 1 } } }
                }
            }
        }
    };

    const layout = getUnpackedLayout(header);
    assert.deepEqual(layout.directories, ['native', 'mixed/build']);
    assert.deepEqual(layout.files, []);
    assert.equal(layout.count, 3);
});

test('repacking preserves unpacked metadata and exposes a stable header hash', async t => {
    const root = temporaryDirectory(t);
    const source = path.join(root, 'source');
    const firstAsar = path.join(root, 'first.asar');
    const extracted = path.join(root, 'extracted');
    const secondAsar = path.join(root, 'second.asar');

    fs.mkdirSync(path.join(source, '.vite', 'build'), { recursive: true });
    fs.mkdirSync(path.join(source, 'native', 'runtime'), { recursive: true });
    fs.writeFileSync(path.join(source, 'package.json'), JSON.stringify({
        name: 'openai-codex-electron',
        version: '26.707.31428',
        codexBuildNumber: '5059',
        codexAppBrand: 'chatgpt',
        main: '.vite/build/early-bootstrap.js'
    }));
    fs.writeFileSync(path.join(source, '.vite', 'build', 'early-bootstrap.js'), 'require("./bootstrap-hash.js");');
    fs.writeFileSync(path.join(source, 'native', 'runtime', 'addon.node'), 'native');
    fs.writeFileSync(path.join(source, 'packed.txt'), 'packed');

    await asar.createPackageWithOptions(source, firstAsar, { unpackDir: 'native' });
    assert.equal(countUnpackedFiles(firstAsar), 1);
    assert.equal(readArchiveManifest(firstAsar).main, '.vite/build/early-bootstrap.js');

    const { options, layout } = createPackOptionsFromHeader(asar.getRawHeader(firstAsar).header);
    assert.equal(layout.count, 1);
    asar.extractAll(firstAsar, extracted);
    await asar.createPackageWithOptions(extracted, secondAsar, options);

    assert.equal(countUnpackedFiles(secondAsar), 1);
    assert.deepEqual(listUnpackedFiles(secondAsar), ['native/runtime/addon.node']);
    assert.match(computeAsarHeaderHash(secondAsar), /^[a-f0-9]{64}$/);
});

test('uses a versioned backup outside the application bundle', () => {
    const backupPath = getBackupPath('/Applications/ChatGPT.app/Contents/Resources/app.asar', {
        name: 'openai-codex-electron',
        version: '26.707.31428',
        codexBuildNumber: '5059',
        codexAppBrand: 'chatgpt'
    }, '/Users/tester');

    assert.equal(
        backupPath,
        '/Users/tester/.codex-rtl/backups/openai-codex-electron-chatgpt/26.707.31428-5059/app.asar'
    );
    assert.ok(!backupPath.startsWith('/Applications/ChatGPT.app/'));
});

test('recognizes a macOS Info.plist next to Resources/app.asar', t => {
    const root = temporaryDirectory(t);
    const contents = path.join(root, 'ChatGPT.app', 'Contents');
    const resources = path.join(contents, 'Resources');
    fs.mkdirSync(resources, { recursive: true });
    fs.writeFileSync(path.join(contents, 'Info.plist'), 'fixture');

    assert.equal(
        getMacInfoPlistPath(path.join(resources, 'app.asar')),
        path.join(contents, 'Info.plist')
    );
    assert.equal(getMacInfoPlistPath(path.join(root, 'app.asar')), null);
});

test('distinguishes an official macOS signature from an ad-hoc signature', () => {
    assert.equal(hasOfficialSignature('Signature=adhoc\nTeamIdentifier=not set\n'), false);
    assert.equal(hasOfficialSignature('Authority=Developer ID Application\nTeamIdentifier=2DC432GLL2\n'), true);
});

test('macOS signing and restore round-trip', { skip: process.platform !== 'darwin' }, t => {
    const root = temporaryDirectory(t);
    const app = path.join(root, 'Fixture.app');
    const contents = path.join(app, 'Contents');
    const resources = path.join(contents, 'Resources');
    const executable = path.join(contents, 'MacOS', 'Fixture');
    const asarPath = path.join(resources, 'app.asar');
    const backupPath = path.join(root, 'backups', 'app.asar');
    const originalPlist = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleExecutable</key><string>Fixture</string>
<key>CFBundleIdentifier</key><string>dev.codex-rtl.fixture</string>
<key>CFBundlePackageType</key><string>APPL</string>
</dict></plist>`;

    fs.mkdirSync(path.dirname(executable), { recursive: true });
    fs.mkdirSync(resources, { recursive: true });
    fs.mkdirSync(path.dirname(backupPath), { recursive: true });
    fs.writeFileSync(path.join(contents, 'Info.plist'), originalPlist);
    fs.copyFileSync('/usr/bin/true', executable);
    fs.chmodSync(executable, 0o755);
    fs.writeFileSync(asarPath, 'original archive');
    execFileSync('/usr/bin/codesign', ['--force', '--sign', '-', app]);
    fs.copyFileSync(asarPath, backupPath);
    ensureMacBundleBackup(asarPath, backupPath);

    fs.writeFileSync(asarPath, 'patched archive');
    fs.appendFileSync(path.join(contents, 'Info.plist'), '\n');
    signMacAppBundle(app);
    const entitlementResult = spawnSync(
        '/usr/bin/codesign',
        ['--display', '--entitlements', ':-', app],
        { encoding: 'utf8' }
    );
    assert.equal(entitlementResult.status, 0);
    const entitlements = `${entitlementResult.stdout}${entitlementResult.stderr}`;
    assert.match(entitlements, /com\.apple\.security\.cs\.allow-jit/);
    assert.match(entitlements, /com\.apple\.security\.cs\.allow-unsigned-executable-memory/);
    assert.match(entitlements, /com\.apple\.security\.cs\.disable-library-validation/);
    assert.doesNotMatch(entitlements, /application-identifier|application-groups|keychain-access-groups/);
    restoreMacBundleBackup(asarPath, backupPath);

    assert.equal(fs.readFileSync(asarPath, 'utf8'), 'original archive');
    assert.equal(fs.readFileSync(path.join(contents, 'Info.plist'), 'utf8'), originalPlist);
});

test('computeIntegrityDictionaryDigest produces expected SHA-256 for sorted dictionary', () => {
    const dict = {
        'Resources/app.asar': {
            algorithm: 'SHA256',
            hash: 'cdfebc59f4a32f4202b12bc26bbc0ff6875fec9491eb2254a5fc0b75eae48d2e'
        }
    };
    const digest = computeIntegrityDictionaryDigest(dict);
    assert.equal(digest.toString('hex'), '0f8538ec9f471984725fdf0f8a172b730176a44f8b2da515c2c7a4ff6a144028');
});

test('macOS framework integrity slot detection and patch', { skip: process.platform !== 'darwin' }, t => {
    const root = temporaryDirectory(t);
    const app = path.join(root, 'Fixture.app');
    const fwDir = path.join(app, 'Contents', 'Frameworks', 'Codex Framework.framework', 'Versions', 'Current');
    fs.mkdirSync(fwDir, { recursive: true });
    const fwBinary = path.join(fwDir, 'Codex Framework');
    
    // Create a dummy binary containing the sentinel slot
    const slot = Buffer.alloc(66);
    ASAR_INTEGRITY_SENTINEL.copy(slot, 0);
    slot[32] = 1; // used
    slot[33] = 1; // version
    Buffer.from('0f8538ec9f471984725fdf0f8a172b730176a44f8b2da515c2c7a4ff6a144028', 'hex').copy(slot, 34);

    const dummyBinary = Buffer.concat([
        Buffer.alloc(100, 0x90),
        slot,
        Buffer.alloc(100, 0x90)
    ]);
    fs.writeFileSync(fwBinary, dummyBinary);

    const slotInfo = findIntegritySlot(fwBinary);
    assert.ok(slotInfo);
    assert.equal(slotInfo.offset, 100);

    const newHash = 'ec439427833c2fd5ce6550e09df0057124ca51ea553c0f1f0427125216f5225d';
    const patched = patchMacFrameworkIntegrity(app, {
        'Resources/app.asar': {
            algorithm: 'SHA256',
            hash: newHash
        }
    });
    assert.equal(patched, true);

    const updatedData = fs.readFileSync(fwBinary);
    const expectedDigest = computeIntegrityDictionaryDigest({
        'Resources/app.asar': {
            algorithm: 'SHA256',
            hash: newHash
        }
    });
    assert.equal(updatedData.subarray(134, 166).toString('hex'), expectedDigest.toString('hex'));
});

test('macOS framework and helper signing and restore round-trip', { skip: process.platform !== 'darwin' }, t => {
    const root = temporaryDirectory(t);
    const app = path.join(root, 'Fixture.app');
    const contents = path.join(app, 'Contents');
    const resources = path.join(contents, 'Resources');
    const executable = path.join(contents, 'MacOS', 'Fixture');
    const asarPath = path.join(resources, 'app.asar');
    const backupPath = path.join(root, 'backups', 'app.asar');
    const originalPlist = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleExecutable</key><string>Fixture</string>
<key>CFBundleIdentifier</key><string>dev.codex-rtl.fixture</string>
<key>CFBundlePackageType</key><string>APPL</string>
</dict></plist>`;

    fs.mkdirSync(path.dirname(executable), { recursive: true });
    fs.mkdirSync(resources, { recursive: true });
    fs.mkdirSync(path.dirname(backupPath), { recursive: true });
    fs.writeFileSync(path.join(contents, 'Info.plist'), originalPlist);
    fs.copyFileSync('/usr/bin/true', executable);
    fs.chmodSync(executable, 0o755);
    fs.writeFileSync(asarPath, 'original archive');

    const fwDir = path.join(contents, 'Frameworks', 'Fixture Framework.framework', 'Versions', 'A');
    const fwCurrent = path.join(contents, 'Frameworks', 'Fixture Framework.framework', 'Versions', 'Current');
    const fwRoot = path.join(contents, 'Frameworks', 'Fixture Framework.framework');
    const fwHelpers = path.join(fwDir, 'Helpers', 'Helper.app', 'Contents', 'MacOS');
    const fwResources = path.join(fwDir, 'Resources');
    fs.mkdirSync(fwDir, { recursive: true });
    fs.mkdirSync(fwHelpers, { recursive: true });
    fs.mkdirSync(fwResources, { recursive: true });
    fs.symlinkSync('A', fwCurrent);
    fs.symlinkSync('Versions/Current/Fixture Framework', path.join(fwRoot, 'Fixture Framework'));
    fs.symlinkSync('Versions/Current/Resources', path.join(fwRoot, 'Resources'));

    const fwPlist = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleExecutable</key><string>Fixture Framework</string>
<key>CFBundleIdentifier</key><string>dev.codex-rtl.fixture.framework</string>
<key>CFBundlePackageType</key><string>FMWK</string>
</dict></plist>`;
    fs.writeFileSync(path.join(fwResources, 'Info.plist'), fwPlist);

    const helperPlist = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleExecutable</key><string>Helper</string>
<key>CFBundleIdentifier</key><string>dev.codex-rtl.fixture.helper</string>
<key>CFBundlePackageType</key><string>APPL</string>
</dict></plist>`;
    fs.writeFileSync(path.join(fwDir, 'Helpers', 'Helper.app', 'Contents', 'Info.plist'), helperPlist);

    const fwBinary = path.join(fwDir, 'Fixture Framework');
    const helperBinary = path.join(fwHelpers, 'Helper');
    fs.copyFileSync('/usr/bin/true', fwBinary);
    fs.copyFileSync('/usr/bin/true', helperBinary);
    fs.chmodSync(fwBinary, 0o755);
    fs.chmodSync(helperBinary, 0o755);

    execFileSync('/usr/bin/codesign', ['--force', '--sign', '-', path.join(fwDir, 'Helpers', 'Helper.app')]);
    execFileSync('/usr/bin/codesign', ['--force', '--sign', '-', path.join(contents, 'Frameworks', 'Fixture Framework.framework')]);
    execFileSync('/usr/bin/codesign', ['--force', '--sign', '-', app]);

    fs.copyFileSync(asarPath, backupPath);
    ensureMacBundleBackup(asarPath, backupPath);

    fs.writeFileSync(asarPath, 'patched archive');
    fs.appendFileSync(path.join(contents, 'Info.plist'), '\n');
    signMacAppBundle(app);

    restoreMacBundleBackup(asarPath, backupPath);
    assert.equal(fs.readFileSync(asarPath, 'utf8'), 'original archive');
    assert.equal(fs.readFileSync(path.join(contents, 'Info.plist'), 'utf8'), originalPlist);
});


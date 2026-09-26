import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { getMacInfoPlistPath } from './asar-utils.js';

const CODESIGN = '/usr/bin/codesign';
const PLIST_BUDDY = '/usr/libexec/PlistBuddy';
export const ASAR_INTEGRITY_SENTINEL = Buffer.from('AGbevlPCksUGKNL8TSn7wGmJEuJsXb2A', 'utf8');

const RUNTIME_ENTITLEMENTS = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "https://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>com.apple.security.cs.allow-jit</key>
    <true/>
    <key>com.apple.security.cs.allow-unsigned-executable-memory</key>
    <true/>
    <key>com.apple.security.cs.disable-library-validation</key>
    <true/>
</dict>
</plist>
`;

export function getMacAppBundlePath(asarPath) {
    const infoPlist = getMacInfoPlistPath(asarPath);
    return infoPlist ? path.dirname(path.dirname(infoPlist)) : null;
}

function run(command, args) {
    const result = spawnSync(command, args, { encoding: 'utf8' });
    if (result.error) throw result.error;
    if (result.status !== 0) {
        throw new Error((result.stderr || result.stdout || `${path.basename(command)} failed`).trim());
    }
    return `${result.stdout || ''}${result.stderr || ''}`;
}

function executableName(infoPlist) {
    const name = run(PLIST_BUDDY, ['-c', 'Print :CFBundleExecutable', infoPlist]).trim();
    if (!name || path.basename(name) !== name) throw new Error('Invalid CFBundleExecutable in Info.plist.');
    return name;
}

export function verifyMacAppBundle(appBundle) {
    run(CODESIGN, ['--verify', '--deep', '--strict', appBundle]);
}

export function hasOfficialSignature(details) {
    const team = details.match(/^TeamIdentifier=(.+)$/m)?.[1]?.trim();
    return !/^Signature=adhoc$/m.test(details) && Boolean(team) && team !== 'not set';
}

export function assertOfficialMacAppBundle(appBundle) {
    verifyMacAppBundle(appBundle);
    const details = run(CODESIGN, ['--display', '--verbose=4', appBundle]);
    if (!hasOfficialSignature(details)) {
        throw new Error('The app is ad-hoc signed. Reinstall the official app before patching it.');
    }
}

export function findMacFramework(appBundle) {
    const frameworksDir = path.join(appBundle, 'Contents', 'Frameworks');
    if (!fs.existsSync(frameworksDir)) return null;
    const entries = fs.readdirSync(frameworksDir);
    for (const entry of entries) {
        if (entry.endsWith('.framework') && !entry.startsWith('Sparkle')) {
            const name = entry.replace(/\.framework$/, '');
            const frameworkPath = path.join(frameworksDir, entry);
            const candidatePaths = [
                path.join(frameworkPath, 'Versions', 'Current', name),
                path.join(frameworkPath, name)
            ];
            for (const binPath of candidatePaths) {
                if (fs.existsSync(binPath) && !fs.statSync(binPath).isDirectory()) {
                    return { frameworkPath, binaryPath: fs.realpathSync(binPath), name };
                }
            }
        }
    }
    return null;
}

export function findHelperApps(frameworkPath) {
    const helpers = [];
    const versionsDir = path.join(frameworkPath, 'Versions');
    if (fs.existsSync(versionsDir)) {
        for (const ver of fs.readdirSync(versionsDir)) {
            const verPath = path.join(versionsDir, ver);
            if (fs.lstatSync(verPath).isSymbolicLink()) continue;
            const helpersDir = path.join(verPath, 'Helpers');
            if (fs.existsSync(helpersDir) && !fs.lstatSync(helpersDir).isSymbolicLink()) {
                for (const helper of fs.readdirSync(helpersDir)) {
                    if (helper.endsWith('.app')) {
                        helpers.push(path.join(helpersDir, helper));
                    }
                }
            }
        }
    }
    return helpers;
}

function helperExecutablePath(helperApp) {
    const infoPlist = path.join(helperApp, 'Contents', 'Info.plist');
    if (fs.existsSync(infoPlist)) {
        const name = executableName(infoPlist);
        const execPath = path.join(helperApp, 'Contents', 'MacOS', name);
        if (fs.existsSync(execPath)) return fs.realpathSync(execPath);
    }
    return null;
}

export function computeIntegrityDictionaryDigest(integrityDict) {
    const keys = Object.keys(integrityDict).sort((a, b) => a.localeCompare(b));
    const hasher = crypto.createHash('sha256');
    for (const key of keys) {
        const item = integrityDict[key];
        hasher.update(key, 'utf8');
        hasher.update(item.algorithm, 'utf8');
        hasher.update(item.hash, 'utf8');
    }
    return hasher.digest();
}

export function findIntegritySlot(binaryPath) {
    if (!fs.existsSync(binaryPath)) return null;
    const data = fs.readFileSync(binaryPath);
    const offset = data.indexOf(ASAR_INTEGRITY_SENTINEL);
    return offset === -1 ? null : { offset };
}

export function patchMacFrameworkIntegrity(appBundle, integrityDict) {
    const fw = findMacFramework(appBundle);
    if (!fw) return false;
    const slotInfo = findIntegritySlot(fw.binaryPath);
    if (!slotInfo) return false;

    const digest = computeIntegrityDictionaryDigest(integrityDict);
    const fd = fs.openSync(fw.binaryPath, 'r+');
    try {
        fs.writeSync(fd, digest, 0, 32, slotInfo.offset + 34);
    } finally {
        fs.closeSync(fd);
    }
    return true;
}

export function getMacBundleBackupPath(asarBackupPath) {
    return path.join(path.dirname(asarBackupPath), 'macos-bundle');
}

function requireCompleteBackup(asarBackupPath) {
    const snapshot = getMacBundleBackupPath(asarBackupPath);
    const infoPlist = path.join(snapshot, 'Info.plist');
    if (!fs.existsSync(asarBackupPath) || !fs.existsSync(infoPlist)) {
        throw new Error('This backup predates macOS signature backups. Reinstall the official app to restore its identity.');
    }
    const executable = executableName(infoPlist);
    if (
        !fs.existsSync(path.join(snapshot, 'MacOS', executable)) ||
        !fs.existsSync(path.join(snapshot, '_CodeSignature'))
    ) {
        throw new Error('The macOS signature backup is incomplete. Reinstall the official app.');
    }
    return { snapshot, infoPlist, executable };
}

export function ensureMacBundleBackup(asarPath, asarBackupPath) {
    const appBundle = getMacAppBundlePath(asarPath);
    if (!appBundle) return null;

    const snapshot = getMacBundleBackupPath(asarBackupPath);
    if (fs.existsSync(snapshot)) {
        requireCompleteBackup(asarBackupPath);
        return snapshot;
    }

    const contents = path.join(appBundle, 'Contents');
    const infoPlist = path.join(contents, 'Info.plist');
    const executable = executableName(infoPlist);
    const codeSignature = path.join(contents, '_CodeSignature');
    if (!fs.existsSync(codeSignature)) throw new Error('The official app has no _CodeSignature directory.');

    const temporary = `${snapshot}.tmp-${process.pid}`;
    fs.rmSync(temporary, { recursive: true, force: true });
    try {
        fs.mkdirSync(path.join(temporary, 'MacOS'), { recursive: true });
        fs.copyFileSync(infoPlist, path.join(temporary, 'Info.plist'));
        fs.copyFileSync(
            path.join(contents, 'MacOS', executable),
            path.join(temporary, 'MacOS', executable)
        );
        fs.cpSync(codeSignature, path.join(temporary, '_CodeSignature'), { recursive: true });

        const fw = findMacFramework(appBundle);
        if (fw) {
            const fwBackupDir = path.join(temporary, 'Framework_Backup');
            fs.mkdirSync(fwBackupDir, { recursive: true });
            const manifest = [];
            let counter = 0;

            const addBackup = (targetPath, isDir) => {
                const backup = `item-${counter++}`;
                if (isDir) fs.cpSync(targetPath, path.join(fwBackupDir, backup), { recursive: true });
                else fs.copyFileSync(targetPath, path.join(fwBackupDir, backup));
                manifest.push({ backup, relative: path.relative(appBundle, targetPath), isDir });
            };

            addBackup(fw.binaryPath, false);

            const versionsDir = path.join(fw.frameworkPath, 'Versions');
            if (fs.existsSync(versionsDir)) {
                for (const ver of fs.readdirSync(versionsDir)) {
                    const verPath = path.join(versionsDir, ver);
                    if (fs.lstatSync(verPath).isSymbolicLink()) continue;
                    const verSig = path.join(verPath, '_CodeSignature');
                    if (fs.existsSync(verSig)) addBackup(verSig, true);
                }
            }

            for (const helper of findHelperApps(fw.frameworkPath)) {
                const execPath = helperExecutablePath(helper);
                if (execPath) addBackup(execPath, false);
                const sigPath = path.join(helper, 'Contents', '_CodeSignature');
                if (fs.existsSync(sigPath)) addBackup(sigPath, true);
            }

            fs.writeFileSync(path.join(fwBackupDir, 'manifest.json'), JSON.stringify(manifest));
        }

        fs.renameSync(temporary, snapshot);
    } finally {
        fs.rmSync(temporary, { recursive: true, force: true });
    }
    return snapshot;
}

function replaceFile(source, destination) {
    fs.mkdirSync(path.dirname(destination), { recursive: true });
    const temporary = `${destination}.codex-rtl-${process.pid}`;
    fs.copyFileSync(source, temporary);
    try {
        fs.renameSync(temporary, destination);
    } finally {
        fs.rmSync(temporary, { force: true });
    }
}

function replaceDirectory(source, destination) {
    fs.mkdirSync(path.dirname(destination), { recursive: true });
    const staged = `${destination}.codex-rtl-${process.pid}`;
    const previous = `${destination}.codex-rtl-old-${process.pid}`;
    fs.rmSync(staged, { recursive: true, force: true });
    fs.rmSync(previous, { recursive: true, force: true });
    fs.cpSync(source, staged, { recursive: true });
    try {
        if (fs.existsSync(destination)) fs.renameSync(destination, previous);
        fs.renameSync(staged, destination);
        fs.rmSync(previous, { recursive: true, force: true });
    } catch (error) {
        if (!fs.existsSync(destination) && fs.existsSync(previous)) fs.renameSync(previous, destination);
        throw error;
    } finally {
        fs.rmSync(staged, { recursive: true, force: true });
    }
}

export function restoreMacBundleBackup(asarPath, asarBackupPath) {
    if (process.platform !== 'darwin') return false;
    const appBundle = getMacAppBundlePath(asarPath);
    if (!appBundle) return false;
    const { snapshot, infoPlist, executable } = requireCompleteBackup(asarBackupPath);
    const contents = path.join(appBundle, 'Contents');

    const fwBackupDir = path.join(snapshot, 'Framework_Backup');
    const fwManifestPath = path.join(fwBackupDir, 'manifest.json');
    if (fs.existsSync(fwManifestPath)) {
        const manifest = JSON.parse(fs.readFileSync(fwManifestPath, 'utf8'));
        for (const item of manifest) {
            const src = path.join(fwBackupDir, item.backup);
            const dest = path.join(appBundle, item.relative);
            if (fs.existsSync(src)) {
                if (item.isDir) replaceDirectory(src, dest);
                else replaceFile(src, dest);
            }
        }
    }

    replaceFile(asarBackupPath, asarPath);
    replaceFile(infoPlist, path.join(contents, 'Info.plist'));
    replaceFile(
        path.join(snapshot, 'MacOS', executable),
        path.join(contents, 'MacOS', executable)
    );
    replaceDirectory(path.join(snapshot, '_CodeSignature'), path.join(contents, '_CodeSignature'));
    verifyMacAppBundle(appBundle);
    return true;
}

export function signMacAppBundle(appBundle) {
    const temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'codex-rtl-entitlements-'));
    const entitlements = path.join(temporary, 'runtime.plist');
    try {
        fs.writeFileSync(entitlements, RUNTIME_ENTITLEMENTS);
        const sign = (target, ents) => run(CODESIGN, [
            '--force', '--sign', '-', '--timestamp=none',
            ...(ents ? ['--preserve-metadata=identifier,flags,runtime', '--entitlements', entitlements] : []),
            target
        ]);

        const fw = findMacFramework(appBundle);
        if (fw) {
            for (const helper of findHelperApps(fw.frameworkPath)) sign(helper, true);
            sign(fw.frameworkPath, false);
        }
        sign(appBundle, true);
    } finally {
        fs.rmSync(temporary, { recursive: true, force: true });
    }
    verifyMacAppBundle(appBundle);
}

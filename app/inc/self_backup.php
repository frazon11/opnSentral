<?php

declare(strict_types=1);

const SELF_BACKUP_FORMAT = 1;
const SELF_BACKUP_DIR = BACKUP_DIR . '/opncentral-self';

function self_backup_safe_filename(string $name): string
{
    $name = preg_replace('/[^A-Za-z0-9._-]+/', '-', trim($name)) ?? '';
    $name = trim($name, '-.');
    return $name !== '' ? $name : 'file';
}

function self_backup_key_fingerprint(): string
{
    return hash('sha256', crypto_key());
}

function self_backup_ensure_directories(): void
{
    foreach ([DATA_DIR, BACKUP_DIR, SELF_BACKUP_DIR] as $directory) {
        if (
            !is_dir($directory) &&
            !mkdir($directory, 0770, true) &&
            !is_dir($directory)
        ) {
            throw new RuntimeException('Could not create directory: ' . $directory);
        }
    }
}

function self_backup_snapshot_database(string $destination): void
{
    $databasePath = DATA_DIR . '/central.sqlite';

    if (!is_file($databasePath)) {
        // Initialising the database is enough to create an empty but valid database.
        db();
    }

    @unlink($destination);

    $quoted = str_replace("'", "''", $destination);
    db()->exec("VACUUM INTO '" . $quoted . "'");

    if (!is_file($destination) || filesize($destination) < 100) {
        throw new RuntimeException('Could not create a consistent SQLite snapshot.');
    }
}

function self_backup_relative_files(
    string $base,
    string $prefix,
    array $excludePrefixes = []
): array {
    if (!is_dir($base)) {
        return [];
    }

    $base = rtrim($base, DIRECTORY_SEPARATOR);
    $files = [];
    $iterator = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator(
            $base,
            FilesystemIterator::SKIP_DOTS
        ),
        RecursiveIteratorIterator::LEAVES_ONLY
    );

    foreach ($iterator as $item) {
        if (!$item->isFile() || $item->isLink()) {
            continue;
        }

        $path = $item->getPathname();
        $relative = ltrim(
            str_replace('\\', '/', substr($path, strlen($base))),
            '/'
        );

        $excluded = false;
        foreach ($excludePrefixes as $exclude) {
            $exclude = trim(str_replace('\\', '/', $exclude), '/');
            if (
                $relative === $exclude ||
                str_starts_with($relative, $exclude . '/')
            ) {
                $excluded = true;
                break;
            }
        }

        if (!$excluded) {
            $files[$prefix . '/' . $relative] = $path;
        }
    }

    return $files;
}

function self_backup_create_archive(
    bool $includeStoredBackups,
    ?string $destination = null,
    string $reason = 'manual'
): array {
    self_backup_ensure_directories();

    $temporaryRoot = sys_get_temp_dir() .
        '/opncentral-self-backup-' .
        bin2hex(random_bytes(8));

    if (
        !mkdir($temporaryRoot, 0700, true) &&
        !is_dir($temporaryRoot)
    ) {
        throw new RuntimeException('Could not create the backup working directory.');
    }

    try {
        $databaseSnapshot = $temporaryRoot . '/central.sqlite';
        self_backup_snapshot_database($databaseSnapshot);

        $files = [
            'data/central.sqlite' => $databaseSnapshot,
        ];

        foreach (
            self_backup_relative_files(
                DATA_DIR,
                'data',
                [
                    'central.sqlite',
                    'central.sqlite-wal',
                    'central.sqlite-shm',
                ]
            ) as $archivePath => $sourcePath
        ) {
            $files[$archivePath] = $sourcePath;
        }

        if ($includeStoredBackups) {
            foreach (
                self_backup_relative_files(
                    BACKUP_DIR,
                    'backups',
                    ['opncentral-self']
                ) as $archivePath => $sourcePath
            ) {
                $files[$archivePath] = $sourcePath;
            }
        }

        $manifestFiles = [];
        foreach ($files as $archivePath => $sourcePath) {
            $size = filesize($sourcePath);
            $sha = hash_file('sha256', $sourcePath);

            if ($size === false || $sha === false) {
                throw new RuntimeException(
                    'Could not calculate integrity information for ' .
                    $archivePath . '.'
                );
            }

            $manifestFiles[$archivePath] = [
                'size' => (int) $size,
                'sha256' => $sha,
            ];
        }

        $manifest = [
            'format' => SELF_BACKUP_FORMAT,
            'application' => 'opnCentral',
            'application_version' => defined('OPNCENTRAL_VERSION')
                ? OPNCENTRAL_VERSION
                : '0.4.5.0',
            'created_at' => gmdate('c'),
            'reason' => $reason,
            'includes_stored_opnsense_backups' => $includeStoredBackups,
            'app_key_fingerprint' => self_backup_key_fingerprint(),
            'app_key_included' => false,
            'restore_requirement' =>
                'Restore with the same APP_KEY used when this archive was created.',
            'files' => $manifestFiles,
        ];

        $manifestPath = $temporaryRoot . '/manifest.json';
        file_put_contents(
            $manifestPath,
            json_encode(
                $manifest,
                JSON_PRETTY_PRINT |
                JSON_UNESCAPED_SLASHES |
                JSON_UNESCAPED_UNICODE |
                JSON_THROW_ON_ERROR
            ),
            LOCK_EX
        );

        if ($destination === null) {
            $destination = sys_get_temp_dir() .
                '/opncentral-backup-' .
                gmdate('Ymd-His') .
                '-' .
                bin2hex(random_bytes(3)) .
                '.zip';
        }

        $zip = new ZipArchive();
        if (
            $zip->open(
                $destination,
                ZipArchive::CREATE | ZipArchive::OVERWRITE
            ) !== true
        ) {
            throw new RuntimeException('Could not create opnCentral backup ZIP.');
        }

        $zip->addFile($manifestPath, 'manifest.json');

        foreach ($files as $archivePath => $sourcePath) {
            if (!$zip->addFile($sourcePath, $archivePath)) {
                $zip->close();
                throw new RuntimeException(
                    'Could not add ' . $archivePath . ' to the archive.'
                );
            }
        }

        if (!$zip->close()) {
            throw new RuntimeException('Could not finalize opnCentral backup ZIP.');
        }

        if (!is_file($destination) || filesize($destination) < 200) {
            throw new RuntimeException('The generated opnCentral backup is invalid.');
        }

        return [
            'path' => $destination,
            'filename' => basename($destination),
            'size' => (int) filesize($destination),
            'manifest' => $manifest,
        ];
    } finally {
        if (is_dir($temporaryRoot)) {
            $iterator = new RecursiveIteratorIterator(
                new RecursiveDirectoryIterator(
                    $temporaryRoot,
                    FilesystemIterator::SKIP_DOTS
                ),
                RecursiveIteratorIterator::CHILD_FIRST
            );
            foreach ($iterator as $item) {
                $item->isDir()
                    ? @rmdir($item->getPathname())
                    : @unlink($item->getPathname());
            }
            @rmdir($temporaryRoot);
        }
    }
}

function self_backup_validate_entry_name(string $name): void
{
    $normalized = str_replace('\\', '/', $name);

    if (
        $normalized === '' ||
        str_starts_with($normalized, '/') ||
        preg_match('#^[A-Za-z]:/#', $normalized) ||
        in_array('..', explode('/', $normalized), true)
    ) {
        throw new RuntimeException(
            'Unsafe path found in uploaded archive: ' . $name
        );
    }
}

function self_backup_validate_archive(string $archivePath): array
{
    if (!is_file($archivePath)) {
        throw new RuntimeException('Uploaded archive was not found.');
    }

    $zip = new ZipArchive();
    if ($zip->open($archivePath) !== true) {
        throw new RuntimeException('The uploaded file is not a readable ZIP archive.');
    }

    try {
        $manifestRaw = $zip->getFromName('manifest.json');
        if ($manifestRaw === false) {
            throw new RuntimeException('manifest.json is missing from the archive.');
        }

        $manifest = json_decode($manifestRaw, true);
        if (!is_array($manifest)) {
            throw new RuntimeException('manifest.json is invalid.');
        }

        if (
            ($manifest['application'] ?? null) !== 'opnCentral' ||
            (int) ($manifest['format'] ?? 0) !== SELF_BACKUP_FORMAT
        ) {
            throw new RuntimeException(
                'This is not a supported opnCentral backup archive.'
            );
        }

        $fingerprint = trim(
            (string) ($manifest['app_key_fingerprint'] ?? '')
        );

        if (
            $fingerprint === '' ||
            !hash_equals(self_backup_key_fingerprint(), $fingerprint)
        ) {
            throw new RuntimeException(
                'APP_KEY mismatch. Restore the original APP_KEY before importing this archive, otherwise encrypted firewall credentials cannot be decrypted.'
            );
        }

        $files = $manifest['files'] ?? null;
        if (!is_array($files) || !isset($files['data/central.sqlite'])) {
            throw new RuntimeException(
                'The archive does not contain the required database snapshot.'
            );
        }

        $seen = [];
        for ($index = 0; $index < $zip->numFiles; $index++) {
            $stat = $zip->statIndex($index);
            if (!is_array($stat) || !isset($stat['name'])) {
                throw new RuntimeException('Could not inspect the uploaded archive.');
            }

            $name = (string) $stat['name'];
            self_backup_validate_entry_name($name);
            $seen[$name] = true;
        }

        foreach ($files as $archiveName => $expected) {
            self_backup_validate_entry_name((string) $archiveName);

            if (
                !str_starts_with((string) $archiveName, 'data/') &&
                !str_starts_with((string) $archiveName, 'backups/')
            ) {
                throw new RuntimeException(
                    'Unsupported file location in archive manifest: ' .
                    $archiveName
                );
            }

            if (!isset($seen[$archiveName])) {
                throw new RuntimeException(
                    'Archive file is missing: ' . $archiveName
                );
            }

            $stream = $zip->getStream((string) $archiveName);
            if ($stream === false) {
                throw new RuntimeException(
                    'Could not read archive file: ' . $archiveName
                );
            }

            $hashContext = hash_init('sha256');
            $actualSize = 0;

            while (!feof($stream)) {
                $chunk = fread($stream, 1048576);
                if ($chunk === false) {
                    fclose($stream);
                    throw new RuntimeException(
                        'Could not read archive file: ' . $archiveName
                    );
                }

                $actualSize += strlen($chunk);
                hash_update($hashContext, $chunk);
            }

            fclose($stream);
            $actualHash = hash_final($hashContext);
            $expectedSize = (int) ($expected['size'] ?? -1);
            $expectedHash = (string) ($expected['sha256'] ?? '');

            if (
                $actualSize !== $expectedSize ||
                !hash_equals($expectedHash, $actualHash)
            ) {
                throw new RuntimeException(
                    'Integrity verification failed for ' . $archiveName . '.'
                );
            }
        }

        return $manifest;
    } finally {
        $zip->close();
    }
}

function self_backup_extract_validated(
    string $archivePath,
    array $manifest,
    string $destination
): void {
    if (
        !mkdir($destination, 0700, true) &&
        !is_dir($destination)
    ) {
        throw new RuntimeException('Could not create restore working directory.');
    }

    $zip = new ZipArchive();
    if ($zip->open($archivePath) !== true) {
        throw new RuntimeException('Could not reopen the uploaded archive.');
    }

    try {
        foreach (array_keys($manifest['files']) as $archiveName) {
            $source = $zip->getStream((string) $archiveName);
            if ($source === false) {
                throw new RuntimeException(
                    'Could not extract ' . $archiveName . '.'
                );
            }

            $target = $destination . '/' . $archiveName;
            $parent = dirname($target);

            if (
                !is_dir($parent) &&
                !mkdir($parent, 0700, true) &&
                !is_dir($parent)
            ) {
                fclose($source);
                throw new RuntimeException(
                    'Could not create restore directory for ' .
                    $archiveName . '.'
                );
            }

            $destinationStream = fopen($target, 'wb');
            if ($destinationStream === false) {
                fclose($source);
                throw new RuntimeException(
                    'Could not create restored file: ' . $archiveName . '.'
                );
            }

            $copied = stream_copy_to_stream($source, $destinationStream);
            fclose($source);
            fclose($destinationStream);

            if ($copied === false) {
                throw new RuntimeException(
                    'Could not extract ' . $archiveName . '.'
                );
            }
        }
    } finally {
        $zip->close();
    }
}

function self_backup_remove_directory_contents(
    string $directory,
    array $preserveRelative = []
): void {
    if (!is_dir($directory)) {
        return;
    }

    $preserveRelative = array_map(
        static fn(string $path): string =>
            trim(str_replace('\\', '/', $path), '/'),
        $preserveRelative
    );

    $iterator = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator(
            $directory,
            FilesystemIterator::SKIP_DOTS
        ),
        RecursiveIteratorIterator::CHILD_FIRST
    );

    foreach ($iterator as $item) {
        $relative = ltrim(
            str_replace(
                '\\',
                '/',
                substr($item->getPathname(), strlen(rtrim($directory, DIRECTORY_SEPARATOR)))
            ),
            '/'
        );

        $preserve = false;
        foreach ($preserveRelative as $keep) {
            if (
                $relative === $keep ||
                str_starts_with($relative, $keep . '/')
            ) {
                $preserve = true;
                break;
            }
        }

        if ($preserve) {
            continue;
        }

        $item->isDir()
            ? @rmdir($item->getPathname())
            : @unlink($item->getPathname());
    }
}

function self_backup_copy_tree(string $source, string $destination): void
{
    if (!is_dir($source)) {
        return;
    }

    if (
        !is_dir($destination) &&
        !mkdir($destination, 0770, true) &&
        !is_dir($destination)
    ) {
        throw new RuntimeException(
            'Could not create restore destination: ' . $destination
        );
    }

    $iterator = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator(
            $source,
            FilesystemIterator::SKIP_DOTS
        ),
        RecursiveIteratorIterator::SELF_FIRST
    );

    foreach ($iterator as $item) {
        $relative = ltrim(
            str_replace('\\', '/', substr($item->getPathname(), strlen($source))),
            '/'
        );
        $target = $destination . '/' . $relative;

        if ($item->isDir()) {
            if (
                !is_dir($target) &&
                !mkdir($target, 0770, true) &&
                !is_dir($target)
            ) {
                throw new RuntimeException(
                    'Could not create restored directory: ' . $relative
                );
            }
        } elseif ($item->isFile()) {
            if (!copy($item->getPathname(), $target)) {
                throw new RuntimeException(
                    'Could not restore file: ' . $relative
                );
            }
            @chmod($target, 0660);
        }
    }
}

function self_backup_restore_archive(string $archivePath): array
{
    self_backup_ensure_directories();
    $manifest = self_backup_validate_archive($archivePath);

    $restoreRoot = sys_get_temp_dir() .
        '/opncentral-self-restore-' .
        bin2hex(random_bytes(8));

    $safetyFilename =
        'safety-before-restore-' .
        gmdate('Ymd-His') .
        '-' .
        bin2hex(random_bytes(3)) .
        '.zip';

    $safetyPath = SELF_BACKUP_DIR . '/' . $safetyFilename;

    // Safety archive is created before any current data is touched.
    self_backup_create_archive(
        true,
        $safetyPath,
        'automatic-safety-before-restore'
    );

    try {
        self_backup_extract_validated($archivePath, $manifest, $restoreRoot);

        $restoredDatabase = $restoreRoot . '/data/central.sqlite';
        $test = new PDO('sqlite:' . $restoredDatabase);
        $test->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $integrity = $test->query('PRAGMA integrity_check')->fetchColumn();
        $test = null;

        if ($integrity !== 'ok') {
            throw new RuntimeException(
                'The restored SQLite database failed integrity checking.'
            );
        }

        // Close the current process-local connection before replacing the file.
        $reflection = new ReflectionFunction('db');
        // The static connection cannot be unset portably, so checkpoint and replace
        // only after all reads/writes for this request are complete.
        db()->exec('PRAGMA wal_checkpoint(TRUNCATE)');

        self_backup_remove_directory_contents(DATA_DIR);
        self_backup_copy_tree($restoreRoot . '/data', DATA_DIR);

        if (
            ($manifest['includes_stored_opnsense_backups'] ?? false) === true
        ) {
            self_backup_remove_directory_contents(
                BACKUP_DIR,
                ['opncentral-self']
            );
            self_backup_copy_tree(
                $restoreRoot . '/backups',
                BACKUP_DIR
            );
        }

        @chmod(DATA_DIR . '/central.sqlite', 0660);

        return [
            'manifest' => $manifest,
            'safety_backup' => $safetyFilename,
            'restart_required' => true,
        ];
    } catch (Throwable $exception) {
        throw new RuntimeException(
            $exception->getMessage() .
            ' Current data was protected by safety backup ' .
            $safetyFilename .
            '.'
        );
    } finally {
        if (is_dir($restoreRoot)) {
            $iterator = new RecursiveIteratorIterator(
                new RecursiveDirectoryIterator(
                    $restoreRoot,
                    FilesystemIterator::SKIP_DOTS
                ),
                RecursiveIteratorIterator::CHILD_FIRST
            );
            foreach ($iterator as $item) {
                $item->isDir()
                    ? @rmdir($item->getPathname())
                    : @unlink($item->getPathname());
            }
            @rmdir($restoreRoot);
        }
    }
}

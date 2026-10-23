# Privacy and permissions — Harbor Terminal 1.1

Harbor Terminal has no analytics or telemetry and runs no remote JavaScript.

## Extension storage

Connection names, colors, terminal URLs, installation identifiers, filenames, directories, verification state and server versions are saved in browser.storage.local. The active connection is also saved in the legacy profile field for compatibility. Existing profiles are migrated without deleting their hosting directory.

Terminal passwords, PHP source, password verifiers and cPanel session URLs are not saved in persistent extension storage. Passwords generated during installation are shown in the settings page until the page is closed or the field is cleared.

When the user clicks the toolbar while on a cPanel File Manager tab, the activeTab permission allows reading that tab URL. It is transferred through browser.storage.session, consumed by the settings page and removed. This temporary state is not synchronized or written to local connection storage. Opening settings and entering the URL manually is also supported. cPanel cookie values are never read or exported; same-origin requests use the existing tab session.

Optional host access is requested separately for the cPanel hostname, selected terminal website and api.github.com. Host permission matching includes HTTPS ports on the approved hostname. scripting is used only for cPanel API calls in the matching authenticated tab; contextMenus adds settings; storage manages connections; activeTab supports the explicit toolbar action.

## Terminal website

The password is verified on the user's host. Command history and favorites are saved in localStorage under that website origin and installation ID; older sessionStorage entries are migrated. Records can include commands, working directories, times, exit codes and duration. The login password field is never recorded. Users can clear history and remove favorites.

Authenticated file tools list and download files accessible to the PHP account, upload a new file without overwriting an existing file, and complete filenames from the selected directory. No file content is sent to a third-party service. Commands run only after the user executes them; selecting suggestions does not execute them.

When private writable temporary storage is available, the PHP file keeps up to 100 live command records on the user's host, session metadata (a hash of the session ID, IP, a shortened user agent and times), login-failure counters and job-control records. Raw session IDs are not stored in that registry. Sessions expire after 15 minutes of inactivity; remote revocation and password changes invalidate previous logins. Revocation does not promise to terminate an already running command. Old session entries are pruned after 24 hours. Five failed login attempts trigger a temporary shared cooldown; when private storage is unavailable, the fallback counter is limited to the current PHP session.

Streaming output, output search, copying and TXT exports go only between the user's browser and own host. Hosting proxies can buffer streaming output. A stop request is handled by the currently running PHP process; stopping all descendants is not guaranteed.

## Upgrade, backup and diagnostics

An explicit host-upgrade action reads only the validated saved terminal file through cPanel UAPI to preserve its instance ID, verifier, salt and fixed-IP restriction. PHP source stays in the open settings page memory. A user can download a private local backup; it contains a password verifier and should not be published. Applying an upgrade or a selected backup overwrites the same validated terminal file. Rollback preserves current authentication values. Neither deployment nor rollback is retried automatically after a lost response.

Diagnostics exports contain connection hostname, check time, extension/terminal/PHP versions and feature flags. They contain no password, cPanel token, PHP source or verifier. Users choose whether to export that local report.

Checking for updates sends only an ordinary HTTPS request to the public GitHub release API; GitHub sees standard connection metadata such as IP. Hosting credentials, file contents, commands and cPanel session URLs are never sent to GitHub. Downloading an extension package does not silently install it.

Removing a connection or uninstalling the extension does not remove the hosting PHP file. Remove that file through File Manager to remove server access. Private server metadata is in an installation-specific temporary folder; web file removal does not promise immediate deletion of that folder.

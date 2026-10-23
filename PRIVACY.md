# Privacy and permissions

Harbor Terminal has no analytics and no telemetry.

- cPanel session URL: entered by the user, held only in the open settings page, and used only in a matching already-authenticated cPanel tab. It is never saved in extension storage or sent to GitHub.
- cPanel cookies: used by same-origin requests inside that tab; the extension never reads or exports cookie values.
- Website content: cPanel domain metadata is read to map the selected directory to its website. The bundled terminal is uploaded to that account only after the user chooses Install.
- Authentication information: a random terminal password is generated locally. Only a PBKDF2 verifier and salt are uploaded inside PHP. Password changes send current and new terminal passwords directly to the selected installation over HTTPS. No password is sent to GitHub or saved in persistent extension storage.
- Local storage: terminal URL, installation identifier, filename, directory and verification state. An unfinished upload record contains the same metadata, without a password or cPanel session URL.
- GitHub: only when Check for updates is selected, a request to the public latest-release API is made. GitHub receives ordinary connection metadata such as the IP address, without hosting credentials.

Optional host permissions are requested separately for your cPanel host, your terminal domain, and api.github.com. Browser host permission matching covers all HTTPS ports on the approved hostname. The extension does not request global host access at installation. `scripting` is used to call cPanel UAPI from your logged-in tab; `contextMenus` adds the settings shortcut; `storage` saves connection metadata. No remote JavaScript is downloaded or executed.

Removing the browser extension does not remove the PHP terminal from your hosting account. Delete its PHP file through File Manager to remove server access. The empty `.harbor-lock-<id>.php` rotation lock can also be removed after deleting the terminal.

## Terminal workspace and upgrades (1.0.2)

The terminal webpage keeps command history and favorites in sessionStorage for that tab, keyed by installation ID. They stay on the terminal website and are not sent to GitHub. A user can clear history or remove favorites. Suggestions fill the editor only; execution requires the Run action. Output copying and TXT export happen locally in the webpage.

When the user explicitly prepares a host upgrade through their logged-in cPanel session, the extension reads only the saved terminal file to preserve its instance ID, password verifier, salt and fixed-IP setting. The PHP source is held in the settings page's memory, never persistent extension storage. A local backup can be downloaded by the user and must be kept private because it contains the verifier. Applying the upgrade overwrites that same validated terminal file; there is no automatic retry or background deployment. No PHP source, verifier, password or cPanel token is sent to GitHub.

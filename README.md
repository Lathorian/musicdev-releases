# MusicDev releases

[Download the latest Windows installer](https://github.com/Lathorian/musicdev-releases/releases/latest/download/MusicDev-Setup-x64.exe). Published installers are hosted on GitHub. The latest link follows the current stable release, and versioned links stay available.

## Publish an update

1. Build the Windows installer and sign `musicdev-update.json` with the MusicDev publisher key. The signing key is kept by the publisher outside this repository.
2. Stage `MusicDev-Setup-x64.exe` with a Send share link. The share includes the key to download the installer and is visible in the release request. Stage only the installer intended for public release.
3. Commit a file named `release-requests/v<VERSION>.json` to `main`. Set `installer_url` to the Send link, `manifest` to the full contents of the signed JSON object, and `notes` to the release notes.

[Publish MusicDev release](https://github.com/Lathorian/musicdev-releases/actions/workflows/publish.yml) verifies the signed manifest and installer before uploading both assets to a draft with its repository-scoped GitHub Actions token. It checks the uploaded digests before making the release public and current. The workflow leaves a draft available to retry if a step fails. Run the workflow manually for the same version to resume an interrupted upload. If the staging link has expired, refresh `installer_url` with a new share for the same signed installer.

MusicDev checks GitHub Releases for new versions. Earlier builds without the updater and builds that cannot launch can use the installer link above.

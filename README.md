# Seisaku releases

Installers and signed updates for Seisaku. The development repository is private.
This repository contains release artifacts and the small publication verifier.

## Linux preview

The initial Linux x86-64 preview is qualified on Fedora 44. Other distributions
are not yet qualified. Download `seisaku-linux-amd64.run` from a published release,
make it executable in your file manager, and open it to start graphical setup.
Setup manages Nexus and offers Nono or MicroVM execution isolation.
GitHub CLI owns GitHub sign-in; Nexus owns provider sign-in.

New installers include the update source. In the application, Updates checks for
releases in the installed channel. Downloading does not install them;
**Update when idle** authorizes activation. Closing the app does not cancel an update.

The source address is `https://github.com/leiringer-ai/seisaku-releases/releases`.
Stable and preview are selected from the installation's signed channel identity.
Update downloads require no GitHub account or access to the development repository.

## Publisher identity

`publisher.pub` contains the Ed25519 public key. Verify its fingerprint through a
trusted source before the first installation. Subsequent updates must match the
installation's retained key; downloading a different key does not change that trust.

## Publication

Releases start as drafts. The manually dispatched Publish workflow downloads the
candidate and verifies its signature, archive digest, and the complete installer
against the pinned public key before publication. It never runs candidate code.
A tag identifies channel, increasing sequence and platform; published assets must
not be replaced. Required runtime Python and JavaScript are distributed with the
application; the development checkout, history, internal docs, tests, login data
and signing key are not included.

Third-party components retain their own licenses and notices within the bundle.

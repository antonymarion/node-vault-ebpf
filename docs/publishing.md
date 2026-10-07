# Publishing

## GitHub

Repository: https://github.com/antonymarion/node-vault-ebpf

```bash
git push -u origin main
git tag v0.1.1
git push origin v0.1.1
```

Tag pushes trigger `.github/workflows/release.yml` (agent tarball + GitHub Release only).

## npm

Package: https://www.npmjs.com/package/node-vault-ebpf

Publish is done **locally** (not via CI):

```bash
npm login
npm run build
npm publish -w node-vault-ebpf --access public
```

2FA / web OTP may be required.

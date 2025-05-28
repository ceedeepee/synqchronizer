# Command Name Fix Summary

## What was fixed

The documentation had inconsistent command names. The npm package provides a binary called `synchronizer` (without 'r'), but documentation was showing `synchronizer-cli` (with 'r').

## Changes Made

### 1. **README.md files** (both synchronizer-cli and synchronizer-repo)
- Fixed all command examples from `synchronizer-cli` to `synchronizer`
- Commands affected:
  - `synchronizer init`
  - `synchronizer start`
  - `synchronizer service`
  - `synchronizer status`
  - `synchronizer web`
  - `synchronizer install-docker`
  - `synchronizer fix-docker`
  - `synchronizer test-platform`
  - `synchronizer service-web`
  - `synchronizer points`
  - `synchronizer set-password`
  - `synchronizer --help`
  - `synchronizer --version`

### 2. **index.js files** (both versions)
- Fixed the web service generation command from `synchronizer-cli web` to `synchronizer web`
- Line fixed: `ExecStart=${npxPath} synchronizer web`

### 3. **License Updates**
- Changed license from MIT to Apache-2.0 in both package.json files
- Updated license badges in README files
- Added LICENSE file to synchronizer-cli directory
- Updated license references in documentation

### 4. **Version Updates**
- synchronizer-cli: 1.10.1 → 1.10.3
- synchronizer-repo: 1.6.0 → 1.6.2

## What remains unchanged

These references correctly remain as `synchronizer-cli`:
- Package name: `synchronizer-cli`
- npm install command: `npm install -g synchronizer-cli`
- Docker image: `cdrakep/synqchronizer:latest`
- Service names: `synchronizer.service`, `synchronizer-web.service`
- Config directory: `~/.synchronizer-cli/`
- Container name: `synchronizer`
- GitHub URLs and references

## Testing

After publishing, users should be able to:
```bash
npm install -g synchronizer-cli
synchronizer --help
synchronizer init
synchronizer start
```

The binary provided by the package.json `bin` field is `synchronizer` (without 'r'), so all command examples must use this form.

## License

Both packages now use Apache-2.0 license consistently across:
- package.json files
- README badges and documentation
- LICENSE files in both directories 
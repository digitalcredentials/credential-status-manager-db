# @digitalcredentials/credential-status-manager-db Changelog

## 2.0.0 - TBD

### Added

- Improve database performance via the following methods:
  - allocate status list indices randomly
  - remove unnecessary CredentialEvent table
  - increase max pool size for MongoDB client
  - allow multiple transactions to run in parallel
  - apply slight modifications to database design to reduce contention

## 1.0.0 - 2024-09-04

### Added

- Initial commit.

# FlowStore Code Signing Policy

## Status

FlowStore has no signed public release and no approved SignPath Foundation subscription. The current GitHub Actions artifacts are unsigned experimental builds. The SignPath application is still a draft and has not been submitted. No binary should be described as signed by SignPath Foundation until the Foundation accepts the application and an artifact carries a verifiable signature.

## Planned signing scope

If the application is accepted, signing will be limited to FlowStore's own Windows release binaries built from this repository by the pinned GitHub Actions workflow. Third-party binaries will not be signed with a FlowStore signing configuration. Each signing request will receive a manual review and approval before release. Published releases will identify the source commit and include SHA-256 checksums and build provenance.

The required release-page disclosure, if and when signing is approved, will be: “Free code signing provided by SignPath.io, certificate by SignPath Foundation”. Until then, the project makes no claim that SignPath provides signing for FlowStore.

## Roles and review

- **Author and maintainer:** the repository owner, [@VivekVRobo](https://github.com/VivekVRobo), maintains the source and build workflow.
- **Reviewer:** the maintainer reviews changes proposed by contributors before merging; changes to release and signing workflows receive particular scrutiny.
- **Signing approver:** the maintainer manually verifies the source commit, CI build provenance, checksums, and release contents before approving any signing request.

Before signing is enabled, every account with repository write access or signing authority must have multi-factor authentication enabled. Access and roles will be reviewed when project membership changes.

## Build and release verification

The current workflow is [`.github/workflows/windows-build.yml`](../.github/workflows/windows-build.yml). It builds the project binaries from source in GitHub Actions and records the source commit and SHA-256 checksums. Future signed releases must use the source and build configuration in this repository, identify the exact source tag/commit, and retain the corresponding CI provenance and checksums with the release.

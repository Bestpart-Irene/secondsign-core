# Releasing

A release is a Git tag. Everything else is automated, so the artefact on PyPI is
always built from the exact commit the tag names.

`secondsign-core` is the distribution name on PyPI; `secondsign` is the import
name.

## One-time setup

Both are configured in a browser and cannot be scripted.

1. **PyPI trusted publisher.** On <https://pypi.org/manage/account/publishing/>,
   add a pending publisher for a project that does not exist yet:

   | Field | Value |
   |---|---|
   | PyPI project name | `secondsign-core` |
   | Owner | `Bestpart-Irene` |
   | Repository name | `secondsign-core` |
   | Workflow name | `release.yml` |
   | Environment name | `pypi` |

   Repeat on <https://test.pypi.org/manage/account/publishing/> with environment
   `testpypi` if you want the rehearsal path.

   No API token is created, and none is stored in the repository. PyPI trusts
   this workflow, in this repository, running in that environment — nothing else.

2. **GitHub environments.** Settings → Environments → `pypi`. Add yourself as a
   required reviewer. An upload cannot be undone or overwritten, so this is the
   last place a mistake is still cheap.

## Cutting a release

```bash
# 1. Bump the single source of truth.
$EDITOR src/secondsign/__init__.py        # __version__ = "0.2.0"

# 2. Ship the bump through the normal review path.
git checkout -b chore/release-0.2.0
git commit -s -am "chore: release 0.2.0"
gh pr create --fill && gh pr merge --merge   # after CI is green

# 3. Tag the merged commit. The tag is the release.
git checkout main && git pull
git tag -a v0.2.0 -m "v0.2.0" && git push origin v0.2.0
```

The workflow then verifies that the tag matches the packaged version, builds the
wheel and sdist, checks the metadata, installs the wheel into a clean
environment and imports it, and waits for the environment approval before
uploading.

To rehearse without touching PyPI: Actions → Release → Run workflow → `testpypi`.

## Rules that are not negotiable

- **A version number is used once.** PyPI does not allow re-uploading a version,
  even after a deletion. A broken release is fixed by a new version, never by
  replacing the old one.
- **The tag matches `__version__`.** The workflow enforces it; do not work
  around it.
- **Pre-1.0 means the interface can change.** Say so in the release notes when
  it does.
- **Publishing is public and permanent.** The sdist contains the source. Do not
  cut a release from a commit you would not want read by anyone, forever.

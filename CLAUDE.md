# keymaster

## Releases

Every GitHub release gets written release notes. An empty body or GitHub's
generated commit list is not enough.

- Read `git log --oneline <previous tag>..HEAD` and the diffs behind it. Write
  for someone running keymaster, not for someone reading the commits.
- Give each user-visible change a `##` section with a short heading. Say what
  changed and why it matters. Leave out internal refactors unless they change
  how keymaster is built or installed.
- End with an `## Upgrading` section whenever the release needs action:
  breaking flags or behaviour, new Keychain prompts, a relay image to
  redeploy, a re-sign after `brew upgrade`
  (`$(brew --prefix)/opt/keymaster/libexec/keymaster-resign`).
- Close with `**Full changelog**: https://github.com/aroberts/keymaster/compare/<previous>...<new>`.
- v0.9.0 and v0.10.0 show the expected shape:
  `gh release view v0.9.0`.

Create the release as a draft with `gh release create <tag> --draft
--notes-file <file>`, and publish it only after the notes are reviewed.
Publishing fires `update-homebrew.yml`, which pushes the new formula to
`aroberts/homebrew-tap`.

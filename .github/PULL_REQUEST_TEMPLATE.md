## Summary

Describe the problem and the focused change.

## Verification

- [ ] `python -m unittest discover -v`
- [ ] `python evaluate_model.py --smoke`
- [ ] `python -m compileall -q application.py netmask flow tests`
- [ ] `node --check static/js/application.js`

## Security and privacy

- [ ] No secrets, personal data, production logs, private PCAPs, or generated artifacts are included.
- [ ] Authorization boundaries and public-target safeguards remain intact.
- [ ] Model/feature compatibility is unchanged or a migration and labeled evaluation are documented.

## Operational impact

Document configuration, dependency, deployment, UI, model, and backward-compatibility changes.
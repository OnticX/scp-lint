Where existing tools stop short

What they don’t do well for SCPs specifically:

Terraform-aware SCP analysis

Understanding SCPs as code

Interactions across multiple SCPs attached at different OU levels

Effective-policy resolution across inheritance

Org-context awareness

Which accounts / OUs are affected

Which services are actually in use

Whether a denied action is theoretical vs used daily

Change-oriented analysis

“What changed compared to the current SCP set?”

“What new actions are denied?”


Core design shift

Instead of:

❌ “This SCP is dangerous”

Do:

✅ “This SCP introduces 37 new denies across 9 services for 12 accounts”


Manual PyPI Publishing Steps
1. One-time setup

pip install build twine
2. Create accounts
Register at https://pypi.org/account/register/
(Optional) Register at https://test.pypi.org for testing first
3. Build the package

cd c:\Users\bodur\scp-lint
python -m build
This creates dist/scp_lint-0.1.0.tar.gz and dist/scp_lint-0.1.0-py3-none-any.whl

4. Test on TestPyPI first (recommended)

twine upload --repository testpypi dist/*
Then test it works: pip install --index-url https://test.pypi.org/simple/ scp-lint

5. Publish to PyPI

twine upload dist/*
You'll be prompted for your PyPI username and password (or API token).

6. For future releases
Update version in pyproject.toml
Delete old dist/ folder: rm -rf dist/
Rebuild: python -m build
Upload: twine upload dist/*
Tip: Use API tokens instead of passwords. Create one at https://pypi.org/manage/account/token/ and use __token__ as username.

What's Missing (Nice to Have for v1)
Resource validation - You validate Actions but not Resources (ARN format)
Duplicate Sid detection - Two statements with same Sid
Duplicate statement detection - Identical statements
NotAction/NotResource warnings - These are tricky and often misused
IP address format validation - When using IpAddress condition operator
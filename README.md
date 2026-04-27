# Agentry

Testing out some agent-related stuff

## TODO

Auth system
- Test stringifying `navigator.credentials.create/get()` - seems to work in Chromium now
- Update request bodies in /api/create-credential and /api/login endpoints to use pydantic templates
- Break out into library
- Set up auto tests with new CLI passkey tool (basic tests working now!)
- Update /verify to return username (in header maybe)
- Add username option to web page
- Python 3.15 will support TOML 1.1, which will allow newlines and trailing
  commas inside {} in keylists
- Postrelease test
- Clean up client

## License

This code is intentionally provided with no license. While you are welcome to read and use it (at your own risk), it is primarily written for my personal use: I offer no guarantee of support, experiment with new and untested techs, and may make breaking changes at any time. If you are risk-averse enough to audit your dependency licenses, you shouldn't be using this repo.

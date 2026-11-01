# vscan-xss-checker
Detects potential XSS vulnerabilities by injecting common XSS payloads into form fields and URL parameters and observing the server's response. A finding requires the payload itself to be reflected in the response, compared against a baseline response fetched without the payload; a page that merely contains a script, image, or svg tag is not a finding. Form actions are resolved against the page URL, so relative actions are tested, and every request carries a timeout. A target that cannot be reached ends as a failed scan at a non-zero exit instead of reporting no vulnerabilities. - Focused on Lightweight web application vulnerability scanning focused on identifying common misconfigurations and publicly known vulnerabilities

## Install
`git clone https://github.com/ShadowStrikeHQ/vscan-xss-checker`

## Usage
`./vscan-xss-checker [params]`

## Parameters
- `-h`: Show help message and exit
- `-p`: Custom XSS payloads to use (optional)
- `-v`: Enable verbose output (debugging)

## License
Copyright (c) ShadowStrikeHQ

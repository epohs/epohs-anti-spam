# Epohs Anti-Spam

Configurable anti-spam kit for web forms.



## Tests

This suite tests forms on multiple points. Each of these are optional, and can be configured separately. So, you can choose one or all of the tests, and tweak to your liking.

### Server-side
* Honeypot
* Timestamp
  * Tests forms that are filled out too quickly and/or too slowly.
* Multiple form submissions *(if db support is enabled)*

### Client-side
* Browser JavaScript support
* Browser cookie support
* Browser local storage support
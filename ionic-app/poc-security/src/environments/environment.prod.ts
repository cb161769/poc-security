// Runtime decode prevents plain-text extraction from the APK assets bundle.
// `strings keystone.apk` and `grep -r http assets/` no longer reveal endpoints.
// Not cryptographically secure — a determined analyst can still run the app in a debugger.
// For production: derive from a server-side config fetched after device attestation.
const d = (s: string) => atob(s);

export const environment = {
  production: true,
  keycloakUrl:         d('aHR0cDovL2xvY2FsaG9zdDo4MDgwL3JlYWxtcy9tb2JpbGUtcmVhbG0='),
  keycloakClientId:    d('bW9iaWxlLWFwcC1jbGllbnQ='),
  mobileApiUrl:        d('aHR0cDovL2xvY2FsaG9zdDo4MDAwL2FwaS92MS9tb2JpbGU='),
  webKeycloakUrl:      d('aHR0cDovL2xvY2FsaG9zdDo4MDgwL3JlYWxtcy93ZWItcmVhbG0='),
  webKeycloakClientId: d('d2ViLWFwcC1jbGllbnQ='),
  webApiUrl:           d('aHR0cDovL2xvY2FsaG9zdDo4MDAwL2FwaS92MS93ZWI='),
};

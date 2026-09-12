// Runtime API/WS base URLs. The hostname is resolved at runtime so the app works
// from localhost and from any LAN address; only the backend port is fixed here.
const host =
  typeof window !== 'undefined' && window.location?.hostname
    ? window.location.hostname
    : 'localhost';

export const environment = {
  production: false,
  apiBaseUrl: `http://${host}:8040`,
  wsBaseUrl: `ws://${host}:8040`,
};

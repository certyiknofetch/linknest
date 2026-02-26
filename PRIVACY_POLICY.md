# Privacy Policy — LinkNest

**Last updated:** February 27, 2026

LinkNest ("the Extension") is a cross-browser bookmark sync extension. This Privacy Policy explains what data the Extension collects, how it is used, and your choices regarding that data.

---

## 1. Data We Collect

### Bookmark Data
The Extension reads your browser's bookmark tree (URLs, titles, and folder structure) to synchronize bookmarks across your browsers. Bookmark data is transmitted to the sync server you configure.

### Account Information
When you register or log in, the Extension collects your name, email address, and password. Passwords are hashed before storage on the server; they are never stored or transmitted in plain text after the initial authentication request.

### Authentication Tokens
After login, the Extension stores a JWT access token and refresh token locally in your browser's storage to maintain your session.

### Sync Preferences
The Extension stores your preferences locally, including server URL, sync interval, auto-sync toggle, and browser name identifier.

---

## 2. How We Use Your Data

- **Bookmark sync:** Bookmark data is sent to and received from your configured sync server to keep bookmarks consistent across browsers.
- **Authentication:** Account credentials are used solely to authenticate you with the sync server.
- **Local storage:** Tokens, preferences, and bookmark hash caches are stored locally in your browser and are never transmitted to any third party.

---

## 3. Data Sharing

We do **not** sell, trade, or share your data with any third parties. Bookmark and account data is only transmitted between the Extension and the sync server you configure (either self-hosted or a server you choose to use).

---

## 4. Data Storage & Security

- Passwords are hashed using bcrypt before server-side storage.
- Authentication uses JWT tokens with expiration.
- All communication with the sync server uses HTTPS (when configured).
- Local data is stored using the browser's built-in extension storage API.

---

## 5. Your Choices

- **Delete your account:** You can remove your account and all associated server-side data by contacting the server administrator or using the server's API.
- **Clear server data:** The Extension provides a "Clear Server Data" button to delete all your bookmarks from the sync server.
- **Uninstall:** Uninstalling the Extension removes all locally stored data (tokens, preferences, caches).

---

## 6. Third-Party Services

The Extension does **not** use any third-party analytics, tracking, or advertising services. The only external communication is with the bookmark sync server you configure.

---

## 7. Children's Privacy

The Extension is not directed at children under 13 and does not knowingly collect personal information from children.

---

## 8. Changes to This Policy

We may update this Privacy Policy from time to time. Changes will be reflected by updating the "Last updated" date above.

---

## 9. Contact

If you have questions about this Privacy Policy, please open an issue on the [LinkNest GitHub repository](https://github.com/your-username/LinkNest/issues).

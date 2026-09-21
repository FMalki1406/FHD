# Project: Next-Generation Cross-Platform Download Manager

I want to build a production-grade, commercial download manager for Windows, macOS, and Linux.

This is NOT an MVP, demo, prototype, or learning project.

The goal is to build a polished, high-performance download manager capable of competing with established download managers while providing a modern user experience, excellent browser integration, strong reliability, privacy, and efficient resource usage.

The architecture must be modular, maintainable, secure, testable, and designed for long-term development.

---

# Technology Stack

Desktop Application:
- Tauri
- React
- TypeScript
- Rust

Core Download Engine:
- Rust
- Tokio async runtime
- Appropriate modern HTTP/networking libraries
- SQLite for persistent local state

Browser Extension:
- TypeScript
- WebExtensions APIs
- Chromium-based browsers
- Firefox
- Architecture that can support Safari later
- Native Messaging where supported for secure communication with the desktop application

Backend:
- TypeScript/Node.js or another suitable production-grade backend stack
- PostgreSQL
- Authentication
- Licensing
- Subscription management
- Device management
- Update/release infrastructure

The download engine must remain independent from the React UI.

React is only the presentation layer.

---

# Core Product Principles

The application should prioritize:

1. Download reliability
2. High download performance
3. Excellent resume/recovery capabilities
4. Excellent browser integration
5. Low CPU and RAM usage
6. Modern UX
7. Privacy
8. Security
9. Cross-platform consistency
10. Extensible architecture

A download should survive:
- Application crashes
- OS restarts
- Network interruptions
- Wi-Fi changes
- Temporary server failures
- Sleep/wake cycles
- Expired URLs when they can be refreshed
- Browser restarts where technically possible

The user should never lose a large download simply because the application crashed or was restarted.

---

# 1. High-Performance Download Engine

Build a robust Rust download engine supporting:

- HTTP
- HTTPS
- HTTP/2
- HTTP/3 where appropriate and supported
- Single-connection downloads
- Multi-connection downloads
- Segmented downloads
- Dynamic segmentation
- Parallel range requests
- Configurable connection count
- Per-host connection limits
- Automatic detection of HTTP Range support
- Automatic fallback to single connection
- Pause
- Resume
- Cancel
- Restart
- Retry
- Exponential backoff
- Redirect handling
- Authentication headers
- Cookies
- Referer
- User-Agent
- Custom headers
- Proxy support
- SOCKS5
- IPv4
- IPv6

The engine must be asynchronous and designed to handle many simultaneous downloads efficiently.

---

# 2. Intelligent Segmentation

Do not implement only static file segmentation.

Create a dynamic segmentation system.

Example:

A 10 GB file may initially be divided across multiple workers.

If one worker receives data significantly faster than another, idle workers should be able to dynamically take remaining ranges.

The engine should intelligently determine:
- Number of connections
- Segment sizes
- Whether segmentation is useful
- Whether the origin server is throttling parallel requests
- When connections should be reduced
- When additional connections could improve performance

Avoid creating unnecessary connections when they provide no performance benefit.

---

# 3. Bulletproof Resume System

Resume reliability is one of the most important features.

Persist enough metadata to safely recover downloads.

Track information such as:
- Download ID
- Original URL
- Current URL
- Redirect chain where useful
- Destination
- Temporary file
- Total size
- Downloaded bytes
- Segment ranges
- Completed ranges
- ETag
- Last-Modified
- MIME type
- Server capabilities
- Relevant request metadata
- Retry state
- Creation time
- Completion state

Before resuming, determine whether the remote resource changed.

Use mechanisms such as:
- ETag
- Last-Modified
- Content-Length
- Range validation

Never silently combine bytes belonging to different versions of a remote file.

---

# 4. Crash Recovery

Use SQLite transactions and safe state persistence.

After an application or operating-system crash:

Application starts
→ inspect incomplete downloads
→ inspect temporary files
→ reconcile persisted state
→ validate remote resources
→ reconstruct segments
→ continue downloads safely

Avoid database corruption and excessive writes.

Download progress should be checkpointed intelligently rather than writing to SQLite for every received chunk.

---

# 5. File Integrity

Support:
- SHA-256
- SHA-512
- Other useful checksums where appropriate

Allow users to provide an expected checksum.

After completion:
Download
→ Finalize
→ Verify
→ Success / Integrity Failure

Never report a download as successfully completed before the file has been safely finalized.

---

# 6. Queue Manager

Create an advanced queue system.

States:
- Waiting
- Connecting
- Downloading
- Paused
- Scheduled
- Verifying
- Completed
- Failed
- Cancelled

Support:
- Multiple queues
- Priorities
- Drag-and-drop ordering
- Maximum concurrent downloads
- Maximum connections globally
- Maximum connections per host
- Queue-specific speed limits
- Automatic retries
- Scheduled queues

---

# 7. Scheduler

Users should be able to create schedules such as:

Start downloads at 01:00
Remove speed limit at 02:00
Stop downloads at 06:00

Support:
- Specific dates
- Recurring schedules
- Days of week
- Start queue
- Stop queue
- Pause queue
- Bandwidth profiles

Where supported and appropriate, optional actions after completion can include:
- Notification
- Sleep
- Shutdown

---

# 8. Smart Bandwidth Management

Provide profiles:

Unlimited
Balanced
Low Impact
Custom

Support:
- Global bandwidth limit
- Per-download limit
- Per-queue limit
- Scheduled limits

Investigate adaptive bandwidth management.

The application should avoid destroying the user's browsing/gaming experience merely because downloads are active.

---

# 9. Browser Extension

Develop extensions for:
- Chrome
- Edge
- Brave and compatible Chromium browsers
- Firefox

Keep the architecture capable of supporting Safari later.

Features:
- Automatically intercept browser downloads
- "Download with [App]" context menu
- Download selected link
- Download selected links
- Download all links on page
- Filter links by file type
- Send download metadata to desktop app
- Detect downloadable media where technically and legally appropriate
- Enable/disable interception
- Domain allowlist
- Domain blocklist
- File-type rules
- Minimum file-size interception rules

---

# 10. Secure Browser/Desktop Communication

Prefer secure browser Native Messaging mechanisms where supported.

Architecture:

Browser
→ Extension
→ Native Messaging Host
→ Desktop Application
→ Rust Download Engine

Do not expose an unauthenticated localhost API.

Validate every message received from the extension.

Treat URLs, filenames, paths, headers, cookies, and metadata from browsers as untrusted input.

---

# 11. Expired URL Recovery

Implement architecture for recovering downloads whose temporary URLs expire.

Example:

Download at 75%
→ signed URL expires
→ server returns authentication/expiration error
→ desktop app requests refreshed URL
→ browser extension obtains updated request information where possible
→ engine verifies that the resource corresponds to the same file
→ download resumes

The system must NEVER assume that a refreshed URL points to the same bytes without validation.

---

# 12. Clipboard Monitoring

Optionally detect downloadable URLs copied to the clipboard.

Provide configurable rules:
- Enabled/disabled
- Domains
- File extensions
- Minimum size where discoverable
- Ignore patterns

Avoid annoying users with constant popups.

---

# 13. Smart File Organization

Automatically classify downloads into categories such as:
- Videos
- Audio
- Images
- Documents
- Archives
- Applications
- Other

Allow custom rules based on:
- Extension
- MIME type
- Domain
- URL pattern
- File size

Example:

*.zip / *.rar / *.7z
→ Downloads/Archives

PDF
→ Downloads/Documents

Allow users to override all automatic behavior.

---

# 14. Duplicate Handling

When a destination already exists, offer configurable behavior:

- Ask
- Rename automatically
- Overwrite
- Skip
- Compare
- Resume when appropriate

Example:

file.zip
file (1).zip
file (2).zip

Never overwrite files unexpectedly.

---

# 15. Batch Downloading

Provide powerful bulk-download tools.

Support:
- Paste multiple URLs
- Import URL list
- Import text/CSV where appropriate
- Generate patterned URLs
- Validate URLs
- Batch rename
- Select/deselect results
- Categorize before downloading

Example pattern:

file001.zip
...
file100.zip

---

# 16. Media Downloads

For downloadable, non-DRM media where downloading is permitted, design modular support for:
- Direct media files
- HLS
- DASH

Possible formats:
- .m3u8
- .mpd

Features may include:
- Stream discovery
- Quality selection
- Audio selection
- Subtitle discovery
- Segment downloading
- Resume
- Parallel segment downloading
- Safe media merging/remuxing

FFmpeg may be used where appropriate, subject to its applicable licensing and distribution requirements.

Do NOT implement DRM circumvention or bypass access controls.

---

# 17. Download Preview

Where technically practical, support previewing certain partially downloaded files.

Examples:
- Video
- Audio
- Images

Design this as an optional module rather than coupling it tightly to the core engine.

---

# 18. Storage Management

Support:
- Disk free-space checks
- Configurable download folders
- Category folders
- Temporary files
- Safe file finalization
- External drives
- Detection of disconnected drives
- Network paths where supported
- Move completed downloads
- Locate missing files
- Cleanup temporary files

Before starting very large downloads, warn when disk space is insufficient.

---

# 19. Download Rules Engine

Create a powerful rules system.

Example:

IF domain = example.com
AND extension = .zip
THEN:
    category = Archives
    folder = D:/Work
    connections = 8
    priority = High

Possible conditions:
- Domain
- URL
- File extension
- MIME
- File size
- Browser source

Possible actions:
- Destination
- Queue
- Priority
- Connection count
- Speed profile
- Auto-start behavior

---

# 20. Search and Filtering

Users may have thousands of downloads.

Provide:
- Instant search
- Status filters
- Category filters
- Domain filters
- Date filters
- Size filters
- Tags
- Sorting

Search should remain fast with a large history.

---

# 21. Statistics

Provide useful statistics such as:
- Downloaded today
- Weekly usage
- Monthly usage
- Average speed
- Peak speed
- Completed downloads
- Failed downloads
- Data downloaded per domain
- Historical bandwidth usage

Do not collect this remotely unless explicitly needed and disclosed.

Prefer local statistics.

---

# 22. Modern Desktop UX

The application must feel like a premium native desktop product, not a website placed inside a window.

Views:

Dashboard
Downloads
Queues
Scheduler
History
Statistics
Settings

Support:
- Light mode
- Dark mode
- System theme
- System tray
- Desktop notifications
- Keyboard shortcuts
- Drag & drop
- Compact mode
- Responsive window sizing
- RTL
- Localization
- Accessibility

A download item should clearly display:

Filename
Progress
Downloaded / Total
Current speed
Average speed
ETA
Status
Connection count

Actions:

Pause
Resume
Cancel
Restart
Open
Open Folder
Copy URL
Properties

---

# 23. Privacy

Use a local-first philosophy.

Download history and URLs should remain on the user's device by default.

Do not send browsing history, download URLs, filenames, or download history to backend servers unless a feature strictly requires it and the user has appropriate notice/control.

Separate:
- Licensing
- Analytics
- Crash reporting
- Download history

Allow optional telemetry/crash reporting to be controlled by the user.

---

# 24. Security

Perform a security review of all trust boundaries.

Protect against:
- Path traversal
- Malicious filenames
- Unsafe redirects
- Header injection
- IPC abuse
- Extension impersonation
- Arbitrary command execution
- Unsafe URL schemes
- Database manipulation
- Malicious update packages

Use:
- TLS verification
- Signed releases
- Signed update manifests/packages
- Secure credential storage using OS facilities where appropriate
- Strict IPC schemas
- Least privilege

Never treat browser-provided data as trusted.

---

# 25. Automatic Updates

Implement secure application updates.

Channels:
- Stable
- Beta
- Nightly/Developer if needed

Support:
- Signed updates
- Update verification
- Release notes
- Rollback/recovery strategy

A failed update must not leave the application unusable.

---

# 26. Cross-Platform Integration

Windows:
- Installer
- Code signing
- System tray
- Notifications
- Startup option
- Protocol handler
- Browser integration

macOS:
- Apple Silicon support
- Intel support if commercially justified
- Code signing
- Notarization
- Keychain integration
- Notifications
- Appropriate permissions

Linux:
Consider:
- AppImage
- .deb
- .rpm
- Desktop integration
- System tray compatibility
- MIME/protocol handlers

Keep OS-specific functionality behind platform abstractions.

---

# 27. Licensing and Commercial Model

Licensing must be completely separated from the download engine.

Architecture:

Desktop App
├── Download Engine
├── Browser Bridge
├── UI
└── Licensing Client
        ↓
    Licensing API

Initial concept:
- 45-day free trial
- Paid plan after trial

Pricing is NOT finalized and must not be hardcoded into the architecture.

Support future possibilities such as:
- Monthly subscription
- Annual subscription
- Lifetime license
- Promotions
- Different plans

Possible licensing capabilities:
- Account
- Device registration
- Device management
- Signed license tokens
- Offline validation
- Offline grace period
- Subscription status
- Restore purchase/subscription

Do not make the application require a constant internet connection solely for license verification.

---

# 28. Performance Targets

Design and benchmark the application for:
- Low idle CPU usage
- Low RAM usage
- Efficient disk writes
- High network throughput
- Thousands of history records
- Multiple concurrent downloads
- Very large files
- Long-running downloads

Do not allow the React UI to receive excessive progress events.

Aggregate/throttle UI progress events while maintaining accurate state inside Rust.

---

# 29. Architecture

Use a modular Rust workspace.

Suggested structure:

download-manager/
├── apps/
│   └── desktop/
│       ├── src/
│       └── src-tauri/
│
├── crates/
│   ├── download-core/
│   ├── http-engine/
│   ├── queue-engine/
│   ├── scheduler/
│   ├── persistence/
│   ├── filesystem/
│   ├── browser-bridge/
│   ├── media/
│   ├── security/
│   └── licensing/
│
├── extensions/
│   ├── chromium/
│   └── firefox/
│
├── backend/
│   ├── auth/
│   ├── licensing/
│   ├── billing/
│   └── releases/
│
└── shared/

Core rule:

React
↓
Tauri commands/events
↓
Rust application layer
↓
Download engine
↓
Networking / SQLite / filesystem

React must NEVER own the authoritative download state.

---

# 30. Download State Machine

Design an explicit state machine.

Example:

CREATED
↓
RESOLVING
↓
CONNECTING
↓
DOWNLOADING
↓
FINALIZING
↓
VERIFYING
↓
COMPLETED

Possible transitions:

DOWNLOADING → PAUSED
DOWNLOADING → RETRY_WAIT
DOWNLOADING → FAILED
DOWNLOADING → CANCELLED

PAUSED → CONNECTING
RETRY_WAIT → CONNECTING

Every transition must be explicit and persisted where necessary.

Avoid scattered boolean flags such as:

isPaused
isFailed
isDownloading
isFinished

Use a well-defined state model.

---

# 31. Observability and Debugging

Build structured logging from the beginning.

Include useful internal events such as:
- Request started
- Redirect
- Range accepted/rejected
- Segment started
- Segment completed
- Retry
- Network failure
- File-system failure
- Verification failure
- State transition

Never log sensitive authentication data, cookies, tokens, or private headers.

Provide an optional diagnostic export that users can attach to bug reports after sensitive information has been removed.

---

# 32. Testing

This product requires serious automated testing.

Unit tests:
- Range calculations
- State transitions
- Filename sanitization
- Retry logic
- Rules engine

Integration tests:
- Resume
- Redirects
- Server without Range support
- Server changing ETag
- Connection loss
- Expired URLs
- Disk full
- Application crash
- Corrupted partial files

Create a local test HTTP server capable of intentionally simulating:
- Slow responses
- Broken connections
- Invalid Content-Length
- Range requests
- No Range support
- Redirect loops
- Changing ETags
- 403
- 404
- 429
- 500/502/503
- Connection resets

The download engine should be heavily tested independently from the UI.

---

# Product Differentiators

The goal is NOT simply to clone an existing download manager.

The product should differentiate itself through the following pillars.

## 1. Reliability First

Make recovery one of the strongest features.

A user downloading a 100 GB file should feel confident that a network failure, application crash, reboot, or sleep cycle will not destroy hours of progress.

## 2. Intelligent Download Engine

Instead of advertising only "16 connections" or "32 connections," dynamically optimize connections and segments based on server behavior and actual throughput.

More connections should not automatically mean better performance.

## 3. Exceptional Browser Integration

Browser integration should feel seamless.

Browser download
→ intercepted instantly
→ desktop download dialog
→ correct filename/folder/rules
→ download

Expired links should be recoverable through browser cooperation where technically possible.

## 4. Modern UX

Many download managers are powerful but visually dated or overloaded.

Provide professional power-user capabilities while keeping common actions simple.

Simple mode for normal users.

Advanced controls when users need them.

## 5. Performance Transparency

Show users useful information about what the engine is doing.

For example:

Connections: 8
Segments: 12
Server Range Support: Yes
Current Speed: 83 MB/s
Average Speed: 76 MB/s
Resume Protection: Active

Advanced users may optionally inspect connection/segment
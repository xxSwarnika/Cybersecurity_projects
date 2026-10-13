/**
 * User interface: file selection, password handling, running the crypto and
 * saving the result. All cryptography lives in crypto.js.
 */
(() => {
  'use strict';

  const $ = id => document.getElementById(id);

  const dom = {
    modeEncrypt: $('mode-encrypt'),
    modeDecrypt: $('mode-decrypt'),
    fileInput: $('file-input'),
    dropzone: $('dropzone'),
    fileCard: $('file-card'),
    fileName: $('file-name'),
    fileMeta: $('file-meta'),
    fileBadge: $('file-badge'),
    clearFile: $('clear-file'),
    passwordLabel: $('password-label'),
    password: $('password'),
    togglePassword: $('toggle-password'),
    generatePassword: $('generate-password'),
    strength: $('strength'),
    strengthFill: $('strength-fill'),
    strengthText: $('strength-text'),
    confirmField: $('confirm-field'),
    confirm: $('password-confirm'),
    confirmText: $('confirm-text'),
    lostWarning: $('lost-warning'),
    run: $('run'),
    status: $('status'),
    result: $('result'),
    resultTitle: $('result-title'),
    resultName: $('result-name'),
    resultDetails: $('result-details'),
    save: $('save'),
    saveNote: $('save-note'),
    fmtIterations: $('fmt-iterations'),
    fmtSalt: $('fmt-salt'),
    fmtIv: $('fmt-iv'),
    fmtCipherSize: $('fmt-cipher-size'),
    fmtTagOffset: $('fmt-tag-offset'),
    fmtTag: $('fmt-tag'),
  };

  const MIN_PASSWORD_LENGTH = 12;
  const GENERATED_LENGTH = 24;
  // No look-alike characters (0/O, 1/l/I), so a generated password is easy to copy by hand.
  const GENERATOR_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!#%&*+-=?@^_~';

  // File types a hosted page may save directly; anything else is wrapped in a .zip.
  const HOST_SAVE_EXTENSIONS = new Set(['gif', 'png', 'jpg', 'jpeg', 'webp', 'mp4', 'webm', 'txt', 'json', 'md',
    'docx', 'pptx', 'epub', 'csv', 'ttf', 'html', 'svg', 'pdf', 'xlsx', 'zip']);

  const EXAMPLE_FILE = {
    name: 'example-meeting-notes.txt',
    type: 'text/plain',
    text: 'Example file for trying Sealbox.\n\nMeeting notes, 13 October\n- Budget review moved to Friday\n- New VPN rollout starts next week\n- Wi-Fi guest password changes monthly\n',
  };

  const state = {
    mode: 'encrypt',
    file: null,     // { name, type, bytes, origin: 'example' | 'picked' | 'zip' }
    result: null,   // { name, type, bytes }
    busy: false,
  };

  // When this page runs inside a host that offers file saving (claude.ai),
  // `downloads` resolves to that service. Standalone, there is no host: undefined.
  let downloads;
  const downloadsReady = window.claude?.use
    ? window.claude.use('downloads').catch(() => null).then(d => (downloads = d))
    : Promise.resolve(undefined);

  // ---------------------------------------------------------------------------
  // Helpers
  // ---------------------------------------------------------------------------

  function formatBytes(n) {
    if (n < 1024) return `${n} B`;
    const units = ['KB', 'MB', 'GB'];
    let value = n;
    let unit = -1;
    do {
      value /= 1024;
      unit++;
    } while (value >= 1024 && unit < units.length - 1);
    return `${value < 10 ? value.toFixed(1) : Math.round(value)} ${units[unit]}`;
  }

  function extensionOf(name) {
    const dot = name.lastIndexOf('.');
    return dot > 0 ? name.slice(dot + 1).toLowerCase() : '';
  }

  function randomPassword(length) {
    const limit = Math.floor(2 ** 32 / GENERATOR_ALPHABET.length) * GENERATOR_ALPHABET.length;
    const buffer = new Uint32Array(1);
    let out = '';
    while (out.length < length) {
      crypto.getRandomValues(buffer);
      if (buffer[0] < limit) out += GENERATOR_ALPHABET[buffer[0] % GENERATOR_ALPHABET.length];
    }
    return out;
  }

  /** Rough entropy: length × log2(character pool). Good enough for a hint. */
  function estimateBits(password) {
    const pool = (/[a-z]/.test(password) ? 26 : 0) + (/[A-Z]/.test(password) ? 26 : 0)
      + (/\d/.test(password) ? 10 : 0) + (/[^A-Za-z0-9]/.test(password) ? 33 : 0);
    return pool ? [...password].length * Math.log2(pool) : 0;
  }

  function setStatus(message, kind = '') {
    dom.status.textContent = message;
    dom.status.className = `status ${kind}`.trim();
  }

  function detailRow(term, value) {
    const dt = document.createElement('dt');
    const dd = document.createElement('dd');
    dt.textContent = term;
    dd.textContent = value;
    return [dt, dd];
  }

  // ---------------------------------------------------------------------------
  // File handling
  // ---------------------------------------------------------------------------

  /** Opens our own zips: if a zip contains a stored .sbox file, use that file instead. */
  function unwrapSealboxZip(name, bytes) {
    if (!Zip.isZip(bytes)) return null;
    const entry = Zip.read(bytes).find(e => e.stored && e.bytes && Sealbox.isSealboxFile(e.bytes));
    return entry ? { name: entry.name, bytes: entry.bytes } : null;
  }

  function setFile({ name, type, bytes }, origin) {
    const unwrapped = unwrapSealboxZip(name, bytes);
    state.file = unwrapped
      ? { name: unwrapped.name, type: '', bytes: unwrapped.bytes, origin: 'zip' }
      : { name, type, bytes, origin };
    state.result = null;
    setMode(Sealbox.isSealboxFile(state.file.bytes) ? 'decrypt' : 'encrypt');
    setStatus('');
  }

  async function handlePickedFile(file) {
    if (!file) return;
    if (file.size > Sealbox.FORMAT.MAX_FILE_BYTES) {
      setStatus(`“${file.name}” is ${formatBytes(file.size)}. Sealbox handles files up to 512 MB.`, 'error');
      return;
    }
    const bytes = new Uint8Array(await file.arrayBuffer());
    setFile({ name: file.name, type: file.type, bytes }, 'picked');
  }

  function loadExample() {
    setFile({ name: EXAMPLE_FILE.name, type: EXAMPLE_FILE.type, bytes: new TextEncoder().encode(EXAMPLE_FILE.text) }, 'example');
  }

  // ---------------------------------------------------------------------------
  // Rendering
  // ---------------------------------------------------------------------------

  function setMode(mode) {
    state.mode = mode;
    state.result = null;
    render();
  }

  function renderFile() {
    const { file, mode } = state;
    dom.fileCard.hidden = !file;
    if (!file) return;

    dom.fileName.textContent = file.name;
    const encrypted = Sealbox.isSealboxFile(file.bytes);
    dom.fileMeta.textContent = `${formatBytes(file.bytes.length)}${encrypted ? ' · Sealbox encrypted' : ''}`;

    let badge = '';
    if (file.origin === 'example') badge = 'Example';
    else if (file.origin === 'zip') badge = 'From zip';
    else if (encrypted && mode === 'decrypt') badge = 'Locked';
    dom.fileBadge.textContent = badge;
  }

  function renderPasswordHelp() {
    const encrypting = state.mode === 'encrypt';
    const password = dom.password.value;

    dom.strength.hidden = !encrypting;
    dom.confirmField.hidden = !encrypting;
    dom.lostWarning.hidden = !encrypting;
    if (!encrypting) return;

    const bits = estimateBits(password);
    const levels = [
      { min: 0, label: 'Too short', color: 'var(--bad)' },
      { min: 50, label: 'Fair', color: 'var(--warn)' },
      { min: 70, label: 'Strong', color: 'var(--good)' },
      { min: 100, label: 'Very strong', color: 'var(--good)' },
    ];
    const tooShort = password.length < MIN_PASSWORD_LENGTH;
    const level = tooShort ? levels[0] : [...levels].reverse().find(l => bits >= l.min);

    dom.strengthFill.style.width = `${Math.min(100, (bits / 120) * 100)}%`;
    dom.strengthFill.style.background = level.color;
    dom.strengthText.textContent = !password ? `Use at least ${MIN_PASSWORD_LENGTH} characters, or press Generate.`
      : tooShort ? `${password.length} of ${MIN_PASSWORD_LENGTH} characters minimum.`
        : `${level.label} · about ${Math.round(bits)} bits`;

    const confirm = dom.confirm.value;
    dom.confirmText.textContent = !confirm ? '' : confirm === password ? 'Passwords match.' : 'Passwords do not match yet.';
  }

  function renderResult() {
    const { result } = state;
    dom.result.hidden = !result;
    if (!result) return;

    dom.resultTitle.textContent = result.title;
    dom.resultName.textContent = result.name;
    dom.resultDetails.replaceChildren(...result.details.flatMap(([term, value]) => detailRow(term, value)));

    const wrapInZip = downloads && !HOST_SAVE_EXTENSIONS.has(extensionOf(result.name));
    dom.save.textContent = wrapInZip ? 'Save as .zip' : 'Save file';
    dom.saveNote.textContent = wrapInZip
      ? 'This host only saves certain file types, so the file comes inside a .zip. Sealbox opens that zip directly, or you can unzip it first.'
      : '';
  }

  function render() {
    const encrypting = state.mode === 'encrypt';
    document.body.classList.toggle('mode-decrypt', !encrypting);
    dom.modeEncrypt.setAttribute('aria-pressed', String(encrypting));
    dom.modeDecrypt.setAttribute('aria-pressed', String(!encrypting));

    dom.passwordLabel.textContent = encrypting ? '2 · Choose a password' : '2 · Enter the password';
    dom.password.autocomplete = encrypting ? 'new-password' : 'current-password';
    dom.generatePassword.hidden = !encrypting;
    dom.run.textContent = state.busy ? (encrypting ? 'Encrypting…' : 'Decrypting…') : (encrypting ? 'Encrypt file' : 'Decrypt file');
    dom.run.disabled = state.busy;

    renderFile();
    renderPasswordHelp();
    renderResult();
  }

  /** Shows the real header values of the file just processed in the format table. */
  function renderFormat(sealedBytes) {
    const { HEADER_BYTES, TAG_BYTES } = Sealbox.FORMAT;
    const header = Sealbox.readHeader(sealedBytes);
    const tagStart = sealedBytes.length - TAG_BYTES;
    dom.fmtIterations.textContent = header.iterations.toLocaleString('en');
    dom.fmtSalt.textContent = Sealbox.toHex(header.salt);
    dom.fmtIv.textContent = Sealbox.toHex(header.iv);
    dom.fmtCipherSize.textContent = (tagStart - HEADER_BYTES).toLocaleString('en');
    dom.fmtTagOffset.textContent = tagStart.toLocaleString('en');
    dom.fmtTag.textContent = Sealbox.toHex(sealedBytes.subarray(tagStart));
  }

  // ---------------------------------------------------------------------------
  // Actions
  // ---------------------------------------------------------------------------

  function validate() {
    if (!state.file) return 'Choose a file first.';
    const password = dom.password.value;
    if (state.mode === 'decrypt') {
      if (!Sealbox.isSealboxFile(state.file.bytes)) return 'This file is not encrypted with Sealbox. Switch to Encrypt to lock it.';
      if (!password) return 'Enter the password the file was encrypted with.';
      return null;
    }
    if (password.length < MIN_PASSWORD_LENGTH) return `Use a password of at least ${MIN_PASSWORD_LENGTH} characters.`;
    if (dom.confirm.value !== password) return 'The two passwords do not match.';
    return null;
  }

  async function encryptFile() {
    const { file } = state;
    const sealed = await Sealbox.encrypt(file.bytes, dom.password.value, { name: file.name, type: file.type });
    const fingerprint = await Sealbox.sha256Hex(sealed.bytes);

    state.result = {
      title: 'Encrypted',
      name: sealed.fileName,
      type: 'application/octet-stream',
      bytes: sealed.bytes,
      details: [
        ['Algorithm', 'AES-256-GCM'],
        ['Key derivation', `PBKDF2-HMAC-SHA256, ${sealed.iterations.toLocaleString('en')} rounds`],
        ['Salt', Sealbox.toHex(sealed.salt)],
        ['IV', Sealbox.toHex(sealed.iv)],
        ['Size', `${formatBytes(file.bytes.length)} → ${formatBytes(sealed.bytes.length)}`],
        ['SHA-256', fingerprint],
      ],
    };
    renderFormat(sealed.bytes);
    // Don't leave the password sitting in the form after it has been used.
    dom.password.value = '';
    dom.confirm.value = '';
    setStatus('Done. Save the encrypted file, and keep your password somewhere safe.', 'success');
  }

  async function decryptFile() {
    const { file } = state;
    const opened = await Sealbox.decrypt(file.bytes, dom.password.value);
    const encryptedAt = opened.encryptedAt ? new Date(opened.encryptedAt).toLocaleString() : 'unknown';

    state.result = {
      title: 'Decrypted',
      name: opened.name,
      type: opened.type || 'application/octet-stream',
      bytes: opened.bytes,
      details: [
        ['Original name', opened.name],
        ['Type', opened.type || 'not recorded'],
        ['Size', formatBytes(opened.bytes.length)],
        ['Encrypted', encryptedAt],
        ['Integrity', 'Verified: the authentication tag matches'],
      ],
    };
    renderFormat(file.bytes);
    dom.password.value = '';
    setStatus('Done. The file is intact and ready to save.', 'success');
  }

  async function run() {
    const problem = validate();
    if (problem) {
      setStatus(problem, 'error');
      return;
    }

    state.busy = true;
    state.result = null;
    setStatus(`Stretching the password with ${Sealbox.FORMAT.DEFAULT_ITERATIONS.toLocaleString('en')} rounds of PBKDF2…`);
    render();

    try {
      if (state.mode === 'encrypt') await encryptFile();
      else await decryptFile();
    } catch (error) {
      setStatus(error instanceof Sealbox.SealboxError ? error.message : `Something went wrong: ${error.message}`, 'error');
    } finally {
      state.busy = false;
      render();
    }
  }

  async function saveResult() {
    const { result } = state;
    if (!result) return;
    await downloadsReady;

    if (downloads === undefined) {
      // Standalone: an ordinary browser download.
      const url = URL.createObjectURL(new Blob([result.bytes], { type: result.type }));
      const link = Object.assign(document.createElement('a'), { href: url, download: result.name });
      document.body.append(link);
      link.click();
      link.remove();
      setTimeout(() => URL.revokeObjectURL(url), 10_000);
      return;
    }

    if (downloads === null) {
      setStatus('Saving files is not available in this view. Download the project and open index.html to save files.', 'error');
      return;
    }

    const wrapInZip = !HOST_SAVE_EXTENSIONS.has(extensionOf(result.name));
    const filename = wrapInZip ? `${result.name}.zip` : result.name;
    const data = wrapInZip ? Zip.create([{ name: result.name, bytes: result.bytes }]) : result.bytes;

    try {
      await downloads.save({ filename, data: new Blob([data]) });
      setStatus(`Saved ${filename}.`, 'success');
    } catch (error) {
      const messages = {
        declined: 'Save cancelled.',
        rate_limited: 'A save prompt is already open.',
        too_large: 'This file is too large to save here.',
      };
      setStatus(messages[error?.code] || 'The file could not be saved here.', error?.code === 'declined' ? '' : 'error');
    }
  }

  function togglePasswordVisibility(show = dom.password.type === 'password') {
    dom.password.type = show ? 'text' : 'password';
    dom.confirm.type = show ? 'text' : 'password';
    dom.togglePassword.textContent = show ? 'Hide' : 'Show';
  }

  function fillGeneratedPassword() {
    const password = randomPassword(GENERATED_LENGTH);
    dom.password.value = password;
    dom.confirm.value = password;
    togglePasswordVisibility(true);
    setStatus('Password generated. Copy it into your password manager before you encrypt.');
    render();
    dom.password.select();
  }

  // ---------------------------------------------------------------------------
  // Wire up
  // ---------------------------------------------------------------------------

  dom.modeEncrypt.addEventListener('click', () => setMode('encrypt'));
  dom.modeDecrypt.addEventListener('click', () => setMode('decrypt'));

  dom.fileInput.addEventListener('change', () => {
    handlePickedFile(dom.fileInput.files[0]);
    dom.fileInput.value = ''; // allows picking the same file again
  });

  ['dragenter', 'dragover'].forEach(type => dom.dropzone.addEventListener(type, event => {
    event.preventDefault();
    dom.dropzone.classList.add('dragging');
  }));
  ['dragleave', 'drop'].forEach(type => dom.dropzone.addEventListener(type, () => dom.dropzone.classList.remove('dragging')));
  dom.dropzone.addEventListener('drop', event => {
    event.preventDefault();
    handlePickedFile(event.dataTransfer.files[0]);
  });

  dom.clearFile.addEventListener('click', () => {
    state.file = null;
    state.result = null;
    setStatus('');
    render();
  });

  dom.password.addEventListener('input', renderPasswordHelp);
  dom.confirm.addEventListener('input', renderPasswordHelp);
  dom.password.addEventListener('keydown', event => { if (event.key === 'Enter') run(); });
  dom.confirm.addEventListener('keydown', event => { if (event.key === 'Enter') run(); });
  dom.togglePassword.addEventListener('click', () => togglePasswordVisibility());
  dom.generatePassword.addEventListener('click', fillGeneratedPassword);
  dom.run.addEventListener('click', run);
  dom.save.addEventListener('click', saveResult);

  // Re-render once we know whether the host can save files (changes the Save button).
  downloadsReady.then(renderResult);

  loadExample();
})();

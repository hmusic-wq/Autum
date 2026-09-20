/* ==========================================================
   電子署名たいけんラボ  script.js
   外部ライブラリなし・ブラウザ単体で動作する。

   構成
     1. SHA-256（ハッシュ関数）… 自前実装（同期処理で、http/https/file どこでも動く）
     2. 便利関数
     3. 鍵と署名のモデル（簡易的な暗号化・復号）
     4. 画面の制御（ステップ①〜③）
   ========================================================== */
'use strict';

/* ==========================================================
   1. SHA-256
   任意の長さのデータ → 32バイト（256ビット）の「指紋」に要約する。
   同じ入力なら必ず同じ値、1ビットでも違えば全く違う値になる。
   ========================================================== */

// 計算に使う定数（SHA-256の仕様で決まっている値）
const K256 = [
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

// 右回転（ビットを右にずらして、はみ出した分を左に戻す）
function rotr(x, n) {
  return (x >>> n) | (x << (32 - n));
}

/**
 * Uint8Array を受け取り、SHA-256 の結果（32バイトのUint8Array）を返す。
 */
function sha256(bytes) {
  const len = bytes.length;

  // 手順1: 末尾に 0x80 を付け、64バイトの倍数になるまで0で埋め、最後に元の長さ（ビット数）を入れる
  const padded = new Uint8Array(((len + 9 + 63) >> 6) << 6);
  padded.set(bytes);
  padded[len] = 0x80;
  const view = new DataView(padded.buffer);
  view.setUint32(padded.length - 8, Math.floor((len * 8) / 0x100000000));
  view.setUint32(padded.length - 4, (len * 8) >>> 0);

  // 手順2: 初期値
  const H = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
  const w = new Uint32Array(64);

  // 手順3: 64バイトずつ混ぜ合わせていく
  for (let offset = 0; offset < padded.length; offset += 64) {
    for (let i = 0; i < 16; i++) w[i] = view.getUint32(offset + i * 4);
    for (let i = 16; i < 64; i++) {
      const s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >>> 3);
      const s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >>> 10);
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
    }

    let [a, b, c, d, e, f, g, h] = H;
    for (let i = 0; i < 64; i++) {
      const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
      const ch = (e & f) ^ (~e & g);
      const t1 = (h + S1 + ch + K256[i] + w[i]) >>> 0;
      const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const t2 = (S0 + maj) >>> 0;
      h = g; g = f; f = e;
      e = (d + t1) >>> 0;
      d = c; c = b; b = a;
      a = (t1 + t2) >>> 0;
    }
    H[0] = (H[0] + a) >>> 0; H[1] = (H[1] + b) >>> 0;
    H[2] = (H[2] + c) >>> 0; H[3] = (H[3] + d) >>> 0;
    H[4] = (H[4] + e) >>> 0; H[5] = (H[5] + f) >>> 0;
    H[6] = (H[6] + g) >>> 0; H[7] = (H[7] + h) >>> 0;
  }

  // 手順4: 8個の32ビット値を並べて32バイトにする
  const out = new Uint8Array(32);
  const outView = new DataView(out.buffer);
  H.forEach((v, i) => outView.setUint32(i * 4, v));
  return out;
}

/* ==========================================================
   2. 便利関数
   ========================================================== */
const encoder = new TextEncoder();

// バイト列 → 16進数の文字列（例：[255, 0] → "ff00"）
function toHex(bytes) {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

// 16進数の文字列 → バイト列
function fromHex(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
  return out;
}

// 文字列のハッシュ値（16進数64文字）を求める
function hashText(text) {
  return toHex(sha256(encoder.encode(text)));
}

/* ==========================================================
   3. 鍵と署名のモデル（簡易版）
   ----------------------------------------------------------
   本物の電子署名（RSAなど）は、数学的に対になった「秘密鍵」「公開鍵」を使う。
   ここでは授業で流れを体験するため、次のように単純化している。

     ・署名する   … ハッシュ値の後ろに目印「SIGN」をつけ、秘密鍵から作った
                    「かぎ文字列」で暗号化（XOR）する
     ・検証する   … 公開鍵（＝対応する鍵）で復号する。
                    対応しない鍵で復号すると、目印「SIGN」が現れず“復号失敗”になる
   ========================================================== */
const PEOPLE = {
  A: { label: 'Aさん（本人）', short: 'Aさん', secret: 'himitsu-no-kagi-of-A-2026' },
  C: { label: 'Cさん（攻撃者）', short: 'Cさん', secret: 'himitsu-no-kagi-of-C-9999' },
};

// 秘密鍵の持ち主から、ハッシュ値と同じ長さ以上の「かぎ文字列」を作る
function keystream(secret, length) {
  const out = new Uint8Array(length);
  let pos = 0;
  let counter = 0;
  while (pos < length) {
    const block = sha256(encoder.encode(secret + ':' + counter++));
    for (let i = 0; i < block.length && pos < length; i++) out[pos++] = block[i];
  }
  return out;
}

const MARK = encoder.encode('SIGN'); // 復号できたかどうかを見分ける目印（4バイト）

function xorBytes(a, b) {
  return a.map((v, i) => v ^ b[i]);
}

/** 秘密鍵で署名する（ハッシュ値 → 電子署名）。戻り値は16進数72文字 */
function signWithPrivateKey(hashHex, person) {
  const payload = new Uint8Array(32 + MARK.length);
  payload.set(fromHex(hashHex));
  payload.set(MARK, 32);
  const key = keystream(PEOPLE[person].secret, payload.length);
  return toHex(xorBytes(payload, key));
}

/**
 * 公開鍵で復号する（電子署名 → ハッシュ値）。
 * 戻り値: { ok: 復号できたか, hashHex: 取り出したハッシュ値（失敗時は意味のない文字列） }
 */
function decryptWithPublicKey(signatureHex, person) {
  const cipher = fromHex(signatureHex);
  const key = keystream(PEOPLE[person].secret, cipher.length);
  const plain = xorBytes(cipher, key);
  const tail = plain.slice(32);
  const ok = tail.length === MARK.length && tail.every((v, i) => v === MARK[i]);
  return { ok, hashHex: toHex(plain.slice(0, 32)) };
}

// 鍵の見分け用の短い番号（表示用）
function keyFingerprint(person) {
  return hashText('id:' + PEOPLE[person].secret).slice(0, 8);
}

// ===== END CRYPTO =====（ここまでは画面に依存しない処理）

/* ==========================================================
   4. 画面の制御
   ========================================================== */
(() => {
  const DEFAULT_MESSAGE = '明日15時に図書室集合';
  const $ = (id) => document.getElementById(id);

  // アプリの状態
  const state = {
    prevHash: null,   // 直前のハッシュ値（変化箇所の黄色表示に使う）
    prevSig: null,    // 直前の署名
    cur: null,        // 今ステップ①で計算されている内容
    sent: null,       // 送信済みの内容（送信ボタンを押した時点のもの）
    lastResult: null, // 直近の判定 'ok' | 'tamper' | 'spoof'
    timers: [],       // 検証アニメーション用のタイマー
  };
  const achieved = new Set(); // 達成したミッション

  /* ---------- 表示用ヘルパー ---------- */

  // HTMLに入れても安全な文字列にする
  function esc(s) {
    return s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  }

  // 16進数の文字列をHTMLにする。8文字ごとにまとめ、ref と違う文字は黄色ハイライト
  function hexHTML(str, ref) {
    let html = '';
    for (let i = 0; i < str.length; i += 8) {
      html += '<span class="hex-group">';
      for (let j = i; j < Math.min(i + 8, str.length); j++) {
        const changed = ref != null && ref[j] !== str[j];
        html += changed ? `<span class="hex-char diff">${str[j]}</span>` : str[j];
      }
      html += '</span>';
    }
    return html;
  }

  // 元の文と今の文を比べ、変わった部分を黄色でくくったHTMLを返す
  function diffText(orig, cur) {
    const o = Array.from(orig);
    const c = Array.from(cur);
    let start = 0;
    while (start < o.length && start < c.length && o[start] === c[start]) start++;
    let endO = o.length;
    let endC = c.length;
    while (endO > start && endC > start && o[endO - 1] === c[endC - 1]) { endO--; endC--; }

    const before = esc(c.slice(0, start).join(''));
    const mid = esc(c.slice(start, endC).join(''));
    const after = esc(c.slice(endC).join(''));
    const changed = orig !== cur;
    const midHTML = mid
      ? `<mark class="diff-mark">${mid}</mark>`
      : changed ? '<mark class="diff-mark">（削除）</mark>' : '';
    return { changed, html: (before + midHTML + after) || '（からっぽ）' };
  }

  /* ---------- ステップ①：送信側 ---------- */

  function getSigner() {
    return document.querySelector('input[name="signKey"]:checked').value;
  }

  // メッセージや鍵が変わるたびに、ハッシュ値と署名を計算し直して表示する
  function updateStep1() {
    const msg = $('msgInput').value;
    const signer = getSigner();

    const hashHex = hashText(msg);                     // メッセージ → ハッシュ値
    const sigHex = signWithPrivateKey(hashHex, signer); // ハッシュ値 → 秘密鍵で暗号化 → 署名

    $('flowMsg').textContent = msg || '（メッセージが空です）';
    $('hashOut').innerHTML = hexHTML(hashHex, state.prevHash);
    $('sigOut').innerHTML = hexHTML(sigHex, state.prevSig);
    $('encChip').textContent = `🔑 ${PEOPLE[signer].short}の秘密鍵（No.${keyFingerprint(signer)}）で暗号化`;

    state.prevHash = hashHex;
    state.prevSig = sigHex;
    state.cur = { msg, signer, hashHex, sigHex };

    $('sendBtn').disabled = msg.trim() === '';

    // 送信後に内容を変えたら、まだ反映されていないことを伝える
    if (state.sent && (state.sent.message !== msg || state.sent.signer !== signer)) {
      $('sendHint').textContent = '※ 変更した内容は、もう一度「送信する」を押すと②に届きます。';
    } else if (!state.sent) {
      $('sendHint').textContent = msg.trim() === '' ? 'メッセージを入力してね。' : '';
    }
  }

  // 「送信する」：署名つきメッセージをステップ②へ
  function send() {
    const c = state.cur;
    if (!c || c.msg.trim() === '') return;

    state.sent = { message: c.msg, signer: c.signer, hashHex: c.hashHex, signature: c.sigHex };
    clearVerify();

    $('tamperInput').value = c.msg;
    $('recvSig').innerHTML = hexHTML(c.sigHex);
    updateDiff();
    setLocked(false);
    $('sendHint').textContent = '送信しました！ ②に届いたよ。';

    // 封筒がとんでいくアニメーション
    const env = $('envelope');
    env.classList.remove('fly');
    void env.offsetWidth; // アニメーションを最初からやり直すためのおまじない
    env.classList.add('fly');

    $('step2').scrollIntoView({ behavior: 'smooth', block: 'center' });
  }

  /* ---------- ステップ②：通信路（改ざん） ---------- */

  // 送信時のメッセージと、今のメッセージの違いを表示
  function updateDiff() {
    if (!state.sent) return;
    const d = diffText(state.sent.message, $('tamperInput').value);
    $('diffView').innerHTML = d.html;
    const chip = $('diffChip');
    chip.textContent = d.changed ? '書き換えられた！' : '書き換えなし';
    chip.className = 'diff-chip ' + (d.changed ? 'changed' : 'same');
  }

  // 「数字を書き換える」ボタン用：15 → 18 のように数字を変える
  function tamperSample(text) {
    if (text.includes('15')) return text.replace('15', '18');
    const m = text.match(/\d+/);
    if (m) return text.replace(m[0], String(parseInt(m[0], 10) + 3));
    return text + '（変更）';
  }

  function setLocked(locked) {
    $('lock2').hidden = !locked;
    $('lock3').hidden = !locked;
    ['tamperInput', 'btnTamperSample', 'btnRestore', 'verifyBtn'].forEach((id) => { $(id).disabled = locked; });
  }

  /* ---------- ステップ③：受信側の検証 ---------- */

  function clearTimers() {
    state.timers.forEach(clearTimeout);
    state.timers = [];
  }

  function clearVerify() {
    clearTimers();
    closeModal();
    state.lastResult = null;
    $('verifyArea').innerHTML =
      '<p class="placeholder">「検証する」を押すと、ルートAとルートBの計算結果がここにならびます。</p>';
  }

  // 受信者が行う検証：ルートA（本文のハッシュ）とルートB（署名を復号）を比べる
  function verify() {
    if (!state.sent) return;
    clearTimers();
    closeModal();

    const received = $('tamperInput').value;           // 届いた本文（改ざんされているかも）
    const hash1 = hashText(received);                  // ルートA：本文 → ハッシュ値1
    const dec = decryptWithPublicKey(state.sent.signature, 'A'); // ルートB：署名 → Aさんの公開鍵で復号
    const hash2 = dec.hashHex;                         // ルートB：ハッシュ値2

    // 判定（順番が大事）
    //   復号に失敗 → Aさん以外の鍵で作られた署名（なりすまし）
    //   復号成功でハッシュ値が違う → 署名のあとで本文が変わった（改ざん）
    //   どちらも問題なし → 成功
    let result;
    if (!dec.ok) result = 'spoof';
    else if (hash1 !== hash2) result = 'tamper';
    else result = 'ok';
    state.lastResult = result;

    renderVerify({ received, hash1, hash2, dec, result });

    state.timers.push(setTimeout(() => openModal(result), 2000));
  }

  function renderVerify({ received, hash1, hash2, dec, result }) {
    const sig = state.sent.signature;
    const matched = result === 'ok';

    const routeBNote = dec.ok
      ? '<p class="route-note ok">✅ 復号できた（Aさんの鍵で作られた署名）</p>'
      : '<p class="route-note ng">❗ 意味のある値に戻せなかった（Aさんの鍵で作られた署名ではない）</p>';

    const compareText = {
      ok: '✅ ハッシュ値1 ＝ ハッシュ値2　一致！',
      tamper: '❌ ハッシュ値1 ≠ ハッシュ値2　本文が署名のときと違う',
      spoof: '⚠️ 署名を復号できず、比べる前にストップ（鍵が不一致）',
    }[result];

    $('verifyArea').innerHTML = `
      <div class="grid gap-4 md:grid-cols-2">
        <div class="route route-a reveal" style="animation-delay:0s">
          <div class="route-title">ルートA　本文から計算</div>
          <div class="flow-block">
            <div class="flow-label">📄 とどいた本文</div>
            <div class="flow-msg">${esc(received) || '（からっぽ）'}</div>
          </div>
          <div class="flow-arrow" aria-hidden="true">
            <svg viewBox="0 0 24 24" class="arrow-svg"><path d="M12 3v15m0 0-6-6m6 6 6-6"/></svg>
            <span class="flow-chip">ハッシュ関数（SHA-256）</span>
          </div>
          <div class="flow-block">
            <div class="flow-label">🧬 ハッシュ値1</div>
            <div class="hexbox mono ${matched ? 'good' : 'bad'}">${hexHTML(hash1, hash2)}</div>
          </div>
        </div>

        <div class="route route-b reveal" style="animation-delay:0.6s">
          <div class="route-title">ルートB　署名を公開鍵で開く</div>
          <div class="flow-block">
            <div class="flow-label">🖋️ とどいた電子署名</div>
            <div class="mono text-sm break-all">${sig.slice(0, 24)}…</div>
          </div>
          <div class="flow-arrow" aria-hidden="true">
            <svg viewBox="0 0 24 24" class="arrow-svg"><path d="M12 3v15m0 0-6-6m6 6 6-6"/></svg>
            <span class="flow-chip flow-chip-blue">🔓 Aさんの公開鍵（No.${keyFingerprint('A')}）で復号</span>
          </div>
          <div class="flow-block">
            <div class="flow-label">🧬 ハッシュ値2</div>
            <div class="hexbox mono ${matched ? 'good' : 'bad'}">${hexHTML(hash2, hash1)}</div>
            ${routeBNote}
          </div>
        </div>
      </div>

      <div class="compare ${matched ? 'ok' : 'ng'} reveal" style="animation-delay:1.3s">
        ${compareText}
        <p class="text-xs font-medium mt-1"><mark class="legend-mark">黄色</mark> は、2つのハッシュ値で違っている文字</p>
      </div>

      <div class="mt-3 text-center reveal" style="animation-delay:1.6s">
        <button type="button" class="btn btn-sub" data-action="reopen">📋 判定をもう一度見る</button>
      </div>`;
  }

  /* ---------- 判定ダイアログ ---------- */

  const RESULT_TEXT = {
    ok: {
      cls: 'success',
      icon: '✅',
      title: '【成功】本人からの送信であり、改ざんはありません',
      desc: 'メッセージから作ったハッシュ値1と、Aさんの公開鍵で署名を開いたハッシュ値2が、完全に一致しました。署名はAさんだけが作れるので「本人からの送信」、指紋が同じなので「途中で変わっていない」と言えます。',
    },
    tamper: {
      cls: 'danger',
      icon: '❌',
      title: '【警告】メッセージが改ざんされています！',
      desc: '署名はAさんの鍵で正しく開けましたが、届いた本文から作ったハッシュ値1が、署名の中のハッシュ値2と違っています。署名を作ったあとで本文が書き換えられたということです。',
    },
    spoof: {
      cls: 'danger',
      icon: '🥷',
      title: '【警告】なりすましの可能性があります（鍵が不一致）',
      desc: 'Aさんの公開鍵では、この署名を正しく開けませんでした。Aさん以外の秘密鍵で作られた署名です。Cさんは、Aさんの秘密鍵を持っていないので、Aさんの署名を作れません。',
    },
  };

  let lastFocus = null;

  function openModal(result) {
    const t = RESULT_TEXT[result];
    $('modalCard').className = 'modal-card ' + t.cls;
    $('modalIcon').textContent = t.icon;
    $('modalTitle').textContent = t.title;
    $('modalDesc').textContent = t.desc;
    lastFocus = document.activeElement;
    $('modal').hidden = false;
    $('modalCard').focus();

    achieved.add(result);
    renderMissions();
  }

  function closeModal() {
    if ($('modal').hidden) return;
    $('modal').hidden = true;
    if (lastFocus && typeof lastFocus.focus === 'function') lastFocus.focus();
  }

  /* ---------- ミッション表示 ---------- */

  function renderMissions() {
    document.querySelectorAll('[data-mission]').forEach((el) => {
      const done = achieved.has(el.dataset.mission);
      el.classList.toggle('done', done);
      el.querySelector('.m-check').textContent = done ? '✅' : '⬜';
    });
  }

  /* ---------- リセット ---------- */

  function resetAll() {
    clearVerify();
    state.sent = null;
    state.prevHash = null;
    state.prevSig = null;
    $('msgInput').value = DEFAULT_MESSAGE;
    document.querySelector('input[name="signKey"][value="A"]').checked = true;
    $('tamperInput').value = '';
    $('recvSig').innerHTML = '';
    $('diffView').textContent = '―';
    $('diffChip').textContent = 'まだ送信していません';
    $('diffChip').className = 'diff-chip';
    $('sendHint').textContent = '';
    setLocked(true);
    updateStep1();
    window.scrollTo({ top: 0, behavior: 'smooth' });
  }

  /* ---------- イベント登録 ---------- */

  $('msgInput').addEventListener('input', updateStep1);
  document.querySelectorAll('input[name="signKey"]').forEach((r) => r.addEventListener('change', updateStep1));
  $('sendBtn').addEventListener('click', send);

  $('tamperInput').addEventListener('input', () => {
    updateDiff();
    clearVerify(); // 本文を変えたら、前の検証結果は古くなるので消す
  });
  $('btnTamperSample').addEventListener('click', () => {
    $('tamperInput').value = tamperSample($('tamperInput').value);
    updateDiff();
    clearVerify();
  });
  $('btnRestore').addEventListener('click', () => {
    if (!state.sent) return;
    $('tamperInput').value = state.sent.message;
    updateDiff();
    clearVerify();
  });

  $('verifyBtn').addEventListener('click', verify);
  $('verifyArea').addEventListener('click', (e) => {
    if (e.target.closest('[data-action="reopen"]') && state.lastResult) openModal(state.lastResult);
  });

  $('modalClose').addEventListener('click', closeModal);
  $('modal').addEventListener('click', (e) => { if (e.target === $('modal')) closeModal(); });
  document.addEventListener('keydown', (e) => { if (e.key === 'Escape') closeModal(); });

  $('resetBtn').addEventListener('click', resetAll);

  /* ---------- 起動 ---------- */
  setLocked(true);
  updateStep1();
  renderMissions();
})();

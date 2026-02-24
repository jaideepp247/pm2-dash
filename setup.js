#!/usr/bin/env node
/**
 * pm2dash setup — create/manage users.json
 * Run: node setup.js
 */
const readline = require('readline');
const bcrypt   = require('bcrypt');
const fs       = require('fs');
const path     = require('path');

const USERS_FILE = path.resolve(__dirname, 'users.json');
const SALT_ROUNDS = 12;

const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
const ask = (q) => new Promise(r => rl.question(q, r));

async function main() {
  console.log('\n  ╔══════════════════════════════╗');
  console.log('  ║   pm2dash — user setup       ║');
  console.log('  ╚══════════════════════════════╝\n');

  let users = [];
  if (fs.existsSync(USERS_FILE)) {
    users = JSON.parse(fs.readFileSync(USERS_FILE, 'utf8'));
    console.log(`  Existing users: ${users.map(u => u.username + (u.readonly ? ' (read-only)' : ' (admin)')).join(', ')}\n`);
  }

  let adding = true;
  while (adding) {
    const username = (await ask('  Username: ')).trim();
    if (!username) { console.log('  Username cannot be empty.\n'); continue; }

    if (users.find(u => u.username === username)) {
      const overwrite = (await ask(`  User "${username}" exists. Overwrite? (y/N): `)).trim().toLowerCase();
      if (overwrite !== 'y') continue;
      users = users.filter(u => u.username !== username);
    }

    const password = (await ask('  Password: ')).trim();
    if (password.length < 6) { console.log('  Password must be at least 6 characters.\n'); continue; }

    const readonlyAns = (await ask('  Read-only? (cannot restart/stop/delete) (y/N): ')).trim().toLowerCase();
    const readonly = readonlyAns === 'y';

    process.stdout.write('  Hashing password...');
    const passwordHash = await bcrypt.hash(password, SALT_ROUNDS);
    process.stdout.write(' done.\n');

    users.push({ username, passwordHash, readonly });
    console.log(`  ✓ User "${username}" added as ${readonly ? 'read-only' : 'admin'}.\n`);

    const cont = (await ask('  Add another user? (y/N): ')).trim().toLowerCase();
    adding = cont === 'y';
    console.log('');
  }

  fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
  console.log(`  ✓ Saved to ${USERS_FILE}`);
  console.log('  Run: node server.js  to start.\n');
  rl.close();
}

main().catch(e => { console.error(e); process.exit(1); });

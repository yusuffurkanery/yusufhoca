import { getStore } from '@netlify/blobs';
import {
  createHmac,
  randomBytes,
  scrypt as callbackScrypt,
  timingSafeEqual,
  createHash,
} from 'node:crypto';
import { promisify } from 'node:util';

const scrypt = promisify(callbackScrypt);
const store = getStore('ocean-quest');
const collections = new Set(['users', 'homeworks', 'rewards', 'questions']);
const sessionTtl = 8 * 60 * 60;
const passwordParams = { N: 16384, r: 8, p: 1, maxmem: 64 * 1024 * 1024 };
const bootstrapAdminPasswordHash = 'scrypt$XgeVjFSB82t1gf3r4PLt2Q$TmsUmz9Lk9i5r4D06xNYr8RaehCqII4qtmB2mF-qNiI7NLYpjl51QlZG8o3VrFZcT1PVa3MpzeK3wrQN0FlQDQ';
const fishLevels = [
  { id: 1, minXp: 0, starMulti: 1 }, { id: 2, minXp: 200, starMulti: 1.1 },
  { id: 3, minXp: 500, starMulti: 1.2 }, { id: 4, minXp: 1000, starMulti: 1.3 },
  { id: 5, minXp: 2000, starMulti: 1.5 }, { id: 6, minXp: 3500, starMulti: 1.7 },
  { id: 7, minXp: 5500, starMulti: 1.9 }, { id: 8, minXp: 8000, starMulti: 2.2 },
  { id: 9, minXp: 12000, starMulti: 2.6 }, { id: 10, minXp: 18000, starMulti: 3 },
];

function response(status, body, cookie) {
  const headers = {
    'cache-control': 'no-store',
    'x-content-type-options': 'nosniff',
    'referrer-policy': 'same-origin',
  };
  if (cookie) headers['set-cookie'] = cookie;
  return new Response(JSON.stringify(body), { status, headers });
}

function normalizeUsername(value) {
  return String(value ?? '').trim().toLocaleLowerCase('tr-TR');
}

function validUsername(value) {
  return /^[\p{L}\p{N}._-]{3,32}$/u.test(value);
}

async function hashPassword(password, salt = randomBytes(16).toString('base64url')) {
  const derived = await scrypt(password, Buffer.from(salt, 'base64url'), 64, passwordParams);
  return `scrypt$${salt}$${Buffer.from(derived).toString('base64url')}`;
}

async function verifyPassword(password, encoded) {
  if (typeof encoded !== 'string') return false;
  const [algorithm, salt, expectedValue] = encoded.split('$');
  if (algorithm !== 'scrypt' || !salt || !expectedValue) return false;
  const expected = Buffer.from(expectedValue, 'base64url');
  const actual = Buffer.from(await hashPassword(password, salt).then((value) => value.split('$')[2]), 'base64url');
  return expected.length === actual.length && timingSafeEqual(expected, actual);
}

async function sessionSecret() {
  let value = await store.get('admin/sessionSecret', { type: 'text' });
  if (!value) {
    value = randomBytes(32).toString('base64url');
    await store.set('admin/sessionSecret', value);
  }
  return value;
}

async function initializeSecurity() {
  const currentHash = await store.get('admin/passwordHash', { type: 'text' });
  if (!currentHash) await store.set('admin/passwordHash', process.env.OCEAN_ADMIN_PASSWORD_HASH ?? bootstrapAdminPasswordHash);
  await sessionSecret();
}

async function signSession(payload) {
  const encoded = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const signature = createHmac('sha256', await sessionSecret()).update(encoded).digest('base64url');
  return `${encoded}.${signature}`;
}

async function readSession(request) {
  const cookie = request.headers.get('cookie') ?? '';
  const token = cookie.split(';').map((part) => part.trim()).find((part) => part.startsWith('ocean_session='))?.slice('ocean_session='.length);
  if (!token) return null;

  const [encoded, suppliedSignature] = token.split('.');
  if (!encoded || !suppliedSignature) return null;
  const expectedSignature = createHmac('sha256', await sessionSecret()).update(encoded).digest();
  const actualSignature = Buffer.from(suppliedSignature, 'base64url');
  if (actualSignature.length !== expectedSignature.length || !timingSafeEqual(actualSignature, expectedSignature)) return null;

  try {
    const payload = JSON.parse(Buffer.from(encoded, 'base64url').toString('utf8'));
    if (!payload.sub || !payload.role || payload.exp < Date.now()) return null;
    return payload;
  } catch {
    return null;
  }
}

async function sessionCookie(payload) {
  const token = await signSession(payload);
  return `ocean_session=${token}; Path=/; Max-Age=${sessionTtl}; HttpOnly; Secure; SameSite=Strict`;
}

function clearSessionCookie() {
  return 'ocean_session=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Strict';
}

function safeUser(user) {
  const { passwordHash, ...publicUser } = user;
  return publicUser;
}

async function getUserByName(username) {
  const id = await store.get(`username/${username}`, { type: 'text' });
  return id ? store.get(`users/${id}`, { type: 'json' }) : null;
}

async function getAuthenticatedUser(request) {
  const session = await readSession(request);
  if (!session) return null;
  if (session.role === 'admin' && session.sub === 'admin') {
    return { role: 'admin', username: 'admin' };
  }
  if (session.role !== 'student') return null;
  const user = await getUserByName(session.sub);
  return user?.role === 'student' ? user : null;
}

async function listCollection(name) {
  const { blobs } = await store.list({ prefix: `${name}/` });
  return Promise.all(blobs.map(({ key }) => store.get(key, { type: 'json' })));
}

function publicProfile(user) {
  return {
    dbId: user.dbId,
    username: user.username,
    role: user.role,
    classId: user.classId,
    xp: user.xp,
    stars: user.stars,
    currentFishId: user.currentFishId,
    homeworks: user.homeworks ?? [],
    accessories: user.accessories ?? [],
    hasEatenToday: user.hasEatenToday ?? false,
  };
}

function fishLevelFor(xp) {
  return [...fishLevels].reverse().find((fish) => xp >= fish.minXp)?.id ?? 1;
}

async function getSnapshot(user) {
  const [users, homeworks, rewards, questions] = await Promise.all([
    listCollection('users'),
    listCollection('homeworks'),
    listCollection('rewards'),
    listCollection('questions'),
  ]);
  const visibleUsers = user.role === 'admin'
    ? users.map(safeUser)
    : users.filter((item) => item.classId === user.classId).map(publicProfile);
  const visibleHomeworks = user.role === 'admin'
    ? homeworks
    : homeworks.filter((item) => !item.targetUser || item.targetUser === user.username)
      .filter((item) => !item.targetClass || item.targetClass === user.classId);
  const visibleQuestions = user.role === 'admin'
    ? questions
    : questions.filter((item) => !item.classId || item.classId === user.classId)
      .map(({ correctIdx, ...question }) => question);

  return {
    user: user.role === 'admin' ? user : publicProfile(user),
    users: visibleUsers,
    homeworks: visibleHomeworks,
    rewards,
    questions: visibleQuestions,
  };
}

function requestIp(request) {
  return request.headers.get('x-nf-client-connection-ip')
    ?? request.headers.get('x-forwarded-for')?.split(',')[0]?.trim()
    ?? 'unknown';
}

async function loginIsRateLimited(request) {
  const ipHash = createHash('sha256').update(requestIp(request)).digest('hex');
  const key = `login-attempts/${ipHash}`;
  const record = await store.get(key, { type: 'json' }) ?? { count: 0, lockedUntil: 0 };
  return { key, record, limited: record.lockedUntil > Date.now() };
}

async function recordFailedLogin(key, record) {
  const count = record.count + 1;
  await store.setJSON(key, {
    count: count >= 8 ? 0 : count,
    lockedUntil: count >= 8 ? Date.now() + 15 * 60 * 1000 : 0,
  });
}

async function readBody(request) {
  const text = await request.text();
  if (text.length > 16_384) throw new Error('Request is too large');
  return text ? JSON.parse(text) : {};
}

function assertSameOrigin(request) {
  const origin = request.headers.get('origin');
  const host = request.headers.get('host');
  if (origin && host && new URL(origin).host !== host) throw new Error('Invalid origin');
}

function validCollection(name) {
  if (!collections.has(name)) throw new Error('Invalid collection');
}

async function handleLogin(request) {
  const { key, record, limited } = await loginIsRateLimited(request);
  if (limited) return response(429, { error: 'Çok fazla başarısız deneme. 15 dakika sonra tekrar deneyin.' });

  const body = await readBody(request);
  const username = normalizeUsername(body.username);
  const password = String(body.password ?? '');
  let user = null;
  let authenticated = false;

  if (username === 'admin') {
    const encodedHash = await store.get('admin/passwordHash', { type: 'text' })
      ?? bootstrapAdminPasswordHash;
    authenticated = await verifyPassword(password, encodedHash);
    user = { role: 'admin', username: 'admin' };
  } else if (validUsername(username)) {
    user = await getUserByName(username);
    authenticated = user?.role === 'student' && await verifyPassword(password, user.passwordHash);
  }

  if (!authenticated || !user) {
    await recordFailedLogin(key, record);
    return response(401, { error: 'Kullanıcı adı veya şifre hatalı.' });
  }

  await store.delete(key);
  const payload = { sub: user.username, role: user.role, exp: Date.now() + sessionTtl * 1000 };
  return response(200, { ok: true }, await sessionCookie(payload));
}

async function handleCreateStudent(request, actor) {
  if (actor.role !== 'admin') return response(403, { error: 'Bu işlem için yönetici girişi gerekli.' });
  const body = await readBody(request);
  const username = normalizeUsername(body.username);
  const password = String(body.password ?? '');
  const classId = String(body.classId ?? '').trim().toLocaleUpperCase('tr-TR');

  if (!validUsername(username)) return response(400, { error: 'Kullanıcı adı 3-32 karakter olmalı; harf, rakam, nokta, tire ve alt çizgi kullanılabilir.' });
  if (password.length < 10 || password.length > 128) return response(400, { error: 'Öğrenci şifresi en az 10 karakter olmalı.' });
  if (!classId || classId.length > 24) return response(400, { error: 'Sınıf bilgisini kontrol edin.' });
  if (await store.get(`username/${username}`, { type: 'text' })) return response(409, { error: 'Bu kullanıcı adı zaten kayıtlı.' });

  const dbId = randomBytes(16).toString('hex');
  const user = {
    dbId,
    username,
    passwordHash: await hashPassword(password),
    role: 'student',
    classId,
    xp: 0,
    stars: 0,
    currentFishId: 1,
    homeworks: [],
    accessories: [],
    hasEatenToday: false,
  };
  await store.setJSON(`users/${dbId}`, user);
  await store.set(`username/${username}`, dbId);
  return response(201, { user: publicProfile(user) });
}

async function handleRecordChange(request, actor) {
  const body = await readBody(request);
  const { operation, collection, id, data } = body;
  validCollection(collection);

  if (operation === 'add') {
    if (collection === 'users') return response(403, { error: 'Öğrencileri yönetici hesabı oluşturabilir.' });
    if (actor.role !== 'admin') {
      if (collection !== 'homeworks' || !String(data?.title ?? '').startsWith('🔴 Avlanma Cezası:')) {
        return response(403, { error: 'Bu işlem için yetkiniz yok.' });
      }
      const target = await getUserByName(normalizeUsername(data.targetUser));
      if (!target || target.classId !== actor.classId) return response(403, { error: 'Yalnızca aynı sınıftaki oyuncular hedeflenebilir.' });
      data.targetUser = target.username;
      data.targetClass = '';
      data.baseXp = 150;
      data.baseStars = 10;
    }
    const dbId = randomBytes(16).toString('hex');
    const item = { ...data, dbId };
    await store.setJSON(`${collection}/${dbId}`, item);
    return response(201, { item });
  }

  if (typeof id !== 'string' || id.length > 80) return response(400, { error: 'Kayıt kimliği geçersiz.' });
  const key = `${collection}/${id}`;
  const current = await store.get(key, { type: 'json' });
  if (!current) return response(404, { error: 'Kayıt bulunamadı.' });

  if (operation === 'update') {
    if (!data || typeof data !== 'object' || Array.isArray(data)) return response(400, { error: 'Güncelleme verisi geçersiz.' });
    if (actor.role === 'student') {
      if (collection !== 'users' || current.dbId !== actor.dbId) return response(403, { error: 'Bu kaydı değiştirme yetkiniz yok.' });
      const previous = current.homeworks ?? [];
      const next = data.homeworks;
      if (Object.keys(data).length !== 1 || !Array.isArray(next) || next.length !== previous.length + 1) {
        return response(403, { error: 'Öğrenci hesabı yalnızca atanmış ödevi teslim edebilir.' });
      }
      if (previous.some((item) => !next.some((candidate) => candidate.hwId === item.hwId && candidate.status === item.status))) {
        return response(403, { error: 'Mevcut ödev teslim kayıtları değiştirilemez.' });
      }
      const added = next.filter((item) => !previous.some((existing) => existing.hwId === item.hwId));
      if (added.length !== 1 || added[0].status !== 'pending' || Object.keys(added[0]).some((field) => !['hwId', 'status'].includes(field))) {
        return response(403, { error: 'Geçersiz ödev teslimi.' });
      }
      const homework = await store.get(`homeworks/${added[0].hwId}`, { type: 'json' });
      if (!homework || (homework.targetUser && homework.targetUser !== current.username)
        || (homework.targetClass && homework.targetClass !== current.classId)) {
        return response(403, { error: 'Bu ödev size atanmamış.' });
      }
    } else if (collection === 'users' && ['username', 'role', 'passwordHash', 'dbId'].some((field) => field in data)) {
      return response(400, { error: 'Hesap kimliği bu ekrandan değiştirilemez.' });
    }
    const updated = { ...current, ...data };
    await store.setJSON(key, updated);
    return response(200, { item: safeUser(updated) });
  }

  if (operation === 'delete') {
    if (actor.role !== 'admin') return response(403, { error: 'Bu işlem için yönetici girişi gerekli.' });
    if (collection === 'users') {
      if (current.role !== 'student') return response(403, { error: 'Yönetici hesabı silinemez.' });
      await store.delete(`username/${current.username}`);
    }
    await store.delete(key);
    return response(200, { ok: true });
  }

  return response(400, { error: 'İşlem türü geçersiz.' });
}

async function handleAdminPasswordChange(request, actor) {
  if (actor.role !== 'admin') return response(403, { error: 'Bu işlem için yönetici girişi gerekli.' });
  const body = await readBody(request);
  const currentPassword = String(body.currentPassword ?? '');
  const newPassword = String(body.newPassword ?? '');
  if (newPassword.length < 12 || newPassword.length > 128) {
    return response(400, { error: 'Yeni şifre 12-128 karakter arasında olmalı.' });
  }
  const currentHash = await store.get('admin/passwordHash', { type: 'text' })
    ?? bootstrapAdminPasswordHash;
  if (!await verifyPassword(currentPassword, currentHash)) {
    return response(401, { error: 'Mevcut şifre hatalı.' });
  }
  if (currentPassword === newPassword) return response(400, { error: 'Yeni şifre mevcut şifreden farklı olmalı.' });
  await store.set('admin/passwordHash', await hashPassword(newPassword));
  return response(200, { ok: true });
}

async function handleStudentAction(request, actor, action) {
  if (actor.role !== 'student') return response(403, { error: 'Bu işlem öğrenci hesabı gerektirir.' });
  const user = await getUserByName(actor.username);
  if (!user) return response(401, { error: 'Öğrenci hesabı bulunamadı.' });
  const body = await readBody(request);

  if (action === 'answers') {
    const question = await store.get(`questions/${body.questionId}`, { type: 'json' });
    if (!question || (question.classId && question.classId !== user.classId)) return response(404, { error: 'Soru bulunamadı.' });
    const correct = Number.isInteger(body.answer) && body.answer === question.correctIdx;
    if (!correct) return response(200, { correct: false });
    const fish = fishLevels.find((item) => item.id === user.currentFishId) ?? fishLevels[0];
    const xp = user.xp + 50;
    const stars = user.stars + Math.floor(5 * fish.starMulti);
    const updated = { ...user, xp, stars, currentFishId: fishLevelFor(xp) };
    await store.setJSON(`users/${user.dbId}`, updated);
    return response(200, { correct: true, xp: 50, stars: stars - user.stars });
  }

  if (action === 'homework-submissions') {
    const homework = await store.get(`homeworks/${body.homeworkId}`, { type: 'json' });
    if (!homework || (homework.targetUser && homework.targetUser !== user.username)
      || (homework.targetClass && homework.targetClass !== user.classId)) {
      return response(404, { error: 'Size atanmış ödev bulunamadı.' });
    }
    const submissions = user.homeworks ?? [];
    if (submissions.some((item) => item.hwId === homework.dbId)) return response(409, { error: 'Bu ödev daha önce teslim edilmiş.' });
    await store.setJSON(`users/${user.dbId}`, { ...user, homeworks: [...submissions, { hwId: homework.dbId, status: 'pending' }] });
    return response(200, { ok: true });
  }

  if (action === 'purchases') {
    const item = await store.get(`rewards/${body.rewardId}`, { type: 'json' });
    if (!item || !Number.isFinite(item.price) || item.price < 0) return response(404, { error: 'Ödül bulunamadı.' });
    if (user.stars < item.price) return response(400, { error: 'Yeterli yıldızın yok.' });
    const accessories = [...(user.accessories ?? [])];
    if (item.type === 'virtual') {
      if (accessories.some((owned) => owned.dbId === item.dbId)) return response(409, { error: 'Bu eşya zaten sende.' });
      if (item.accType === 'aura') {
        const auraIndex = accessories.findIndex((owned) => owned.accType === 'aura');
        if (auraIndex >= 0) accessories.splice(auraIndex, 1);
      }
      accessories.push({ ...item });
    }
    await store.setJSON(`users/${user.dbId}`, { ...user, stars: user.stars - item.price, accessories });
    return response(200, { ok: true });
  }

  if (action === 'hunts') {
    const prey = await store.get(`users/${body.preyId}`, { type: 'json' });
    if (!prey || prey.role !== 'student' || prey.dbId === user.dbId || prey.classId !== user.classId) {
      return response(404, { error: 'Aynı sınıftaki oyuncu bulunamadı.' });
    }
    if (user.currentFishId - prey.currentFishId < 3) return response(403, { error: 'Avlanmak için avın senden en az 3 seviye küçük olmalı.' });
    const xp = user.xp + 100;
    await store.setJSON(`users/${user.dbId}`, { ...user, xp, currentFishId: fishLevelFor(xp) });
    const dbId = randomBytes(16).toString('hex');
    await store.setJSON(`homeworks/${dbId}`, {
      dbId,
      title: '🔴 Avlanma Cezası: 10 Matematik Sorusu',
      desc: 'Okyanusta güçlü bir balığa yem oldun! Hayatta kalmayı öğrenmek ve güçlenmek için öğretmeninden 10 matematik sorusu iste ve çöz.',
      targetClass: '', targetUser: prey.username, baseXp: 150, baseStars: 10,
    });
    return response(200, { ok: true, username: prey.username });
  }

  return response(404, { error: 'İşlem bulunamadı.' });
}

export default async function handler(request) {
  try {
    const route = new URL(request.url).pathname.split('/').filter(Boolean).at(-1);
    await initializeSecurity();
    if (request.method === 'GET' && route === 'health') {
      return response(200, { ready: true });
    }
    if (request.method !== 'GET') assertSameOrigin(request);

    if (request.method === 'POST' && route === 'login') return await handleLogin(request);
    if (request.method === 'POST' && route === 'logout') return response(200, { ok: true }, clearSessionCookie());

    const actor = await getAuthenticatedUser(request);
    if (!actor) return response(401, { error: 'Oturum açmanız gerekiyor.' });

    if (request.method === 'GET' && route === 'data') {
      const user = actor.role === 'admin' ? actor : await getUserByName(actor.username);
      if (!user) return response(401, { error: 'Oturum geçersiz.' });
      return response(200, await getSnapshot(user));
    }
    if (request.method === 'POST' && ['answers', 'homework-submissions', 'purchases', 'hunts'].includes(route)) {
      return await handleStudentAction(request, actor, route);
    }
    if (request.method === 'POST' && route === 'password') return await handleAdminPasswordChange(request, actor);
    if (request.method === 'POST' && route === 'students') return await handleCreateStudent(request, actor);
    if (request.method === 'POST' && route === 'records') return await handleRecordChange(request, actor);
    return response(404, { error: 'İstek bulunamadı.' });
  } catch (error) {
    console.error('Ocean Quest API error:', error);
    const message = error.message === 'Invalid origin' ? 'İstek kaynağı doğrulanamadı.' : 'İşlem tamamlanamadı.';
    return response(error.message === 'Invalid origin' ? 403 : 500, { error: message });
  }
}

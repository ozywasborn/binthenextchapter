import express from 'express';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';
import cors from 'cors';
import crypto from 'crypto';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = 3000;
const DATA_DIR = path.join(__dirname, 'data');
const DB_FILE = path.join(DATA_DIR, 'activities.json');
const DELETED_FILE = path.join(DATA_DIR, 'deleted_ids.json');

// Ensure data directory exists
if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

// Helpers to read/write deleted IDs tombstones
function getDeletedIds() {
  try {
    if (!fs.existsSync(DELETED_FILE)) {
      return [];
    }
    const data = fs.readFileSync(DELETED_FILE, 'utf-8');
    const parsed = JSON.parse(data);
    return Array.isArray(parsed) ? parsed : [];
  } catch (err) {
    console.error('Error reading deleted IDs DB:', err);
    return [];
  }
}

function saveDeletedIds(ids) {
  try {
    const unique = Array.from(new Set(ids.map(String)));
    fs.writeFileSync(DELETED_FILE, JSON.stringify(unique, null, 2), 'utf-8');
    return true;
  } catch (err) {
    console.error('Error saving deleted IDs DB:', err);
    return false;
  }
}

function recordDeletedId(id) {
  const current = getDeletedIds();
  const toAdd = [];
  if (id) {
    toAdd.push(String(id));
    if (String(id).startsWith('drive_')) {
      toAdd.push(String(id).replace(/^drive_/, ''));
    }
  }
  const combined = [...current, ...toAdd];
  saveDeletedIds(combined);
}

// Server-side robust activity deduplication
function deduplicateActivities(list) {
  if (!Array.isArray(list)) return [];
  const seenIds = new Set();
  const result = [];

  for (const item of list) {
    if (!item) continue;
    const id = String(item.id || '');
    const title = String(item.title || '').trim().toLowerCase();
    const date = String(item.date || '').trim();
    const amount = Math.round((parseFloat(item.amount) || 0) * 10) / 10;
    const category = String(item.category || '').trim();

    // Check direct ID match
    if (id && seenIds.has(id)) {
      continue;
    }

    // Check content duplicate
    const existingMatch = result.find(r => {
      const matchBasic = 
        String(r.title || '').trim().toLowerCase() === title &&
        String(r.date || '').trim() === date &&
        (Math.round((parseFloat(r.amount) || 0) * 10) / 10) === amount &&
        String(r.category || '').trim() === category;
      if (!matchBasic) return false;
      if (item.imgUrl && r.imgUrl && item.imgUrl === r.imgUrl) return true;
      const timeDiff = Math.abs((item.createdAt || 0) - (r.createdAt || 0));
      return timeDiff < 120000;
    });

    if (existingMatch) {
      if (item.imgUrl && !existingMatch.imgUrl) {
        existingMatch.imgUrl = item.imgUrl;
      }
      continue;
    }

    if (id) seenIds.add(id);
    result.push({ ...item, amount });
  }

  return result;
}

// Helpers to read/write database
function getActivities() {
  try {
    if (!fs.existsSync(DB_FILE)) {
      return [];
    }
    const data = fs.readFileSync(DB_FILE, 'utf-8');
    const parsed = JSON.parse(data);
    const deleted = new Set(getDeletedIds().map(String));
    const active = Array.isArray(parsed) ? parsed.filter(a => {
      if (!a) return false;
      const id = String(a.id || '');
      if (id && deleted.has(id)) return false;
      return true;
    }) : [];
    return deduplicateActivities(active);
  } catch (err) {
    console.error('Error reading activities DB:', err);
    return [];
  }
}

function saveActivities(activities) {
  try {
    const deleted = new Set(getDeletedIds().map(String));
    const active = Array.isArray(activities) ? activities.filter(a => {
      if (!a) return false;
      const id = String(a.id || '');
      if (id && deleted.has(id)) return false;
      return true;
    }) : [];
    const deduped = deduplicateActivities(active);
    fs.writeFileSync(DB_FILE, JSON.stringify(deduped, null, 2), 'utf-8');
    return true;
  } catch (err) {
    console.error('Error saving activities DB:', err);
    return false;
  }
}

// Load Firebase configuration
let firebaseConfig = null;
const configPath = path.join(__dirname, 'firebase-applet-config.json');
if (fs.existsSync(configPath)) {
  try {
    firebaseConfig = JSON.parse(fs.readFileSync(configPath, 'utf-8'));
  } catch (err) {
    console.warn('Could not parse firebase-applet-config.json:', err.message);
  }
}

app.use(cors());
app.use(express.json({ limit: '100mb' }));
app.use(express.urlencoded({ extended: true, limit: '100mb' }));

// Expose Firebase config for frontend client-side Firestore connection
app.get('/api/firebase-config', (req, res) => {
  if (firebaseConfig) {
    return res.json({ success: true, config: firebaseConfig });
  }
  res.status(404).json({ success: false, message: 'Firebase configuration not found' });
});

// Expose deleted IDs list
app.get('/api/deleted-ids', (req, res) => {
  res.json({ success: true, deletedIds: getDeletedIds() });
});

// Verify Deletion PIN securely without embedding raw pin code in source code
const PIN_SALT = 'btnc_delete_v1_';
const PIN_HASH_DIGEST = '77a6d8b02aa6298eb48a016bb0b782d8f76e0399ba2bec74b8f4a6a2f9d31914';

app.post('/api/verify-pin', (req, res) => {
  const { pin } = req.body;
  if (!pin) {
    return res.status(400).json({ success: false, message: 'PIN is required' });
  }
  const customPin = process.env.DELETE_PIN;
  if (customPin) {
    return res.json({ valid: String(pin).trim() === String(customPin).trim() });
  }
  const hash = crypto.createHash('sha256').update(PIN_SALT + String(pin).trim()).digest('hex');
  return res.json({ valid: hash === PIN_HASH_DIGEST });
});

// Serve static site files
app.use(express.static(__dirname));

// API Endpoints
// 1. Get all activities
app.get('/api/activities', (req, res) => {
  const activities = getActivities();
  res.json({ success: true, data: activities });
});

// 2. Add or Upsert an activity
app.post('/api/activities', (req, res) => {
  const incomingId = req.body.id || Date.now().toString();
  const deleted = new Set(getDeletedIds().map(String));
  if (deleted.has(String(incomingId))) {
    return res.status(200).json({ success: false, message: 'Activity was previously deleted' });
  }

  const rawAmount = parseFloat(req.body.amount) || 0;
  const roundedAmount = Math.round(rawAmount * 10) / 10;
  const title = req.body.title || 'Untitled';
  const date = req.body.date || new Date().toISOString().split('T')[0];

  const activities = getActivities();
  const newActivity = {
    id: incomingId,
    title: title,
    description: req.body.description || '',
    date: date,
    amount: roundedAmount,
    unit: req.body.unit || 'km',
    category: req.body.category || 'Others',
    imgUrl: req.body.imgUrl || null,
    createdAt: req.body.createdAt || Date.now()
  };

  const existingIdx = activities.findIndex(a => a.id === incomingId);
  if (existingIdx !== -1) {
    activities[existingIdx] = {
      ...activities[existingIdx],
      ...newActivity,
      id: activities[existingIdx].id
    };
  } else {
    activities.unshift(newActivity);
  }

  saveActivities(activities);
  res.status(201).json({ success: true, data: newActivity });
});

// 3. Update an activity
app.put('/api/activities/:id', (req, res) => {
  const { id } = req.params;
  const activities = getActivities();
  const index = activities.findIndex(a => a.id === id);
  if (index === -1) {
    return res.status(404).json({ success: false, message: 'Activity not found' });
  }

  const updatedPayload = { ...req.body };
  if (updatedPayload.amount !== undefined) {
    const rawAmount = parseFloat(updatedPayload.amount) || 0;
    updatedPayload.amount = Math.round(rawAmount * 10) / 10;
  }

  activities[index] = { ...activities[index], ...updatedPayload, id };
  saveActivities(activities);
  res.json({ success: true, data: activities[index] });
});

// 4. Delete an activity
app.delete('/api/activities/:id', (req, res) => {
  const { id } = req.params;
  let activities = getActivities();
  recordDeletedId(id);

  activities = activities.filter(a => String(a.id) !== String(id));
  saveActivities(activities);
  res.json({ success: true, message: 'Activity deleted successfully', deletedId: id });
});

app.get('*', (req, res, next) => {
  if (req.path.startsWith('/api/')) {
    return next();
  }
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running at http://0.0.0.0:${PORT}`);
});

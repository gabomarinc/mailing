const express = require('express');
const cors = require('cors');
const path = require('path');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const { SESClient, SendEmailCommand, VerifyDomainIdentityCommand, VerifyDomainDkimCommand, GetIdentityVerificationAttributesCommand, GetIdentityDkimAttributesCommand } = require('@aws-sdk/client-ses');
const { neon } = require('@neondatabase/serverless');
const { Pool } = require('pg');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// Configurar base de datos Neon
const dbUrl = process.env.DATABASE_URL || 'postgresql://user:pass@ep-host.neon.tech/db?sslmode=require';
const sql = neon(dbUrl);
const pool = new Pool({ connectionString: dbUrl });

// Utilidades
function isValidEmail(email) {
  const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return re.test(String(email).toLowerCase());
}

// Inicializar tablas en Neon
async function initDB() {
  try {
    await sql`
      CREATE TABLE IF NOT EXISTS users (
          kinde_id VARCHAR(255) PRIMARY KEY,
          company_name VARCHAR(255),
          monthly_volume INTEGER,
          is_setup_complete BOOLEAN DEFAULT false
      );
    `;
    await sql`
      CREATE TABLE IF NOT EXISTS contacts (
          id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
          kinde_id VARCHAR(255) NOT NULL REFERENCES users(kinde_id) ON DELETE CASCADE,
          name VARCHAR(255) NOT NULL,
          email VARCHAR(255) NOT NULL,
          tags TEXT[],
          custom_fields JSONB DEFAULT '{}'::jsonb,
          status VARCHAR(50) DEFAULT 'active',
          added_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
      );
    `;
    await sql`
      CREATE TABLE IF NOT EXISTS campaigns (
          id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
          kinde_id VARCHAR(255) NOT NULL REFERENCES users(kinde_id) ON DELETE CASCADE,
          subject VARCHAR(255) NOT NULL,
          body TEXT NOT NULL,
          target_tags TEXT[],
          total_sent INTEGER DEFAULT 0,
          status VARCHAR(50) DEFAULT 'sent',
          sent_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
      );
    `;
    await sql`
      CREATE TABLE IF NOT EXISTS senders (
          id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
          kinde_id VARCHAR(255) NOT NULL REFERENCES users(kinde_id) ON DELETE CASCADE,
          name VARCHAR(255) NOT NULL,
          email VARCHAR(255) NOT NULL,
          is_verified BOOLEAN DEFAULT true,
          dkim_status BOOLEAN DEFAULT true,
          dmarc_status BOOLEAN DEFAULT true,
          created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
      );
    `;
    await sql`
      CREATE TABLE IF NOT EXISTS domains (
          id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
          kinde_id VARCHAR(255) NOT NULL REFERENCES users(kinde_id) ON DELETE CASCADE,
          domain_name VARCHAR(255) NOT NULL,
          dkim_tokens TEXT[],
          verification_status VARCHAR(50) DEFAULT 'Pending',
          dkim_status VARCHAR(50) DEFAULT 'Pending',
          created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
      );
    `;
    await sql`
      CREATE TABLE IF NOT EXISTS dedicated_ips (
          id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
          kinde_id VARCHAR(255) NOT NULL REFERENCES users(kinde_id) ON DELETE CASCADE,
          ip_address VARCHAR(50),
          status VARCHAR(50) DEFAULT 'requested',
          requested_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
          assigned_at TIMESTAMP WITH TIME ZONE
      );
    `;
    
    // Add columns if they don't exist
    try {
      await sql`ALTER TABLE users ADD COLUMN hourly_limit INTEGER DEFAULT 1000`;
    } catch(e) { /* Column might exist */ }
    try {
      await sql`ALTER TABLE users ADD COLUMN warmup_mode BOOLEAN DEFAULT false`;
    } catch(e) { /* Column might exist */ }
    await sql`CREATE INDEX IF NOT EXISTS idx_contacts_kinde_id ON contacts(kinde_id);`;
    await sql`CREATE INDEX IF NOT EXISTS idx_campaigns_kinde_id ON campaigns(kinde_id);`;
    await sql`CREATE INDEX IF NOT EXISTS idx_senders_kinde_id ON senders(kinde_id);`;
    
    await sql`
      CREATE TABLE IF NOT EXISTS "session" (
        "sid" varchar NOT NULL COLLATE "default",
        "sess" json NOT NULL,
        "expire" timestamp(6) NOT NULL
      ) WITH (OIDS=FALSE);
    `;
    await sql`
      DO $$
      BEGIN
          IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'session_pkey') THEN
              ALTER TABLE "session" ADD CONSTRAINT "session_pkey" PRIMARY KEY ("sid") NOT DEFERRABLE INITIALLY IMMEDIATE;
          END IF;
      END
      $$;
    `;
    await sql`
      CREATE INDEX IF NOT EXISTS "IDX_session_expire" ON "session" ("expire");
    `;

    // MIGRATION: ADD custom_fields if not exists
    await sql`
      ALTER TABLE contacts ADD COLUMN IF NOT EXISTS custom_fields JSONB DEFAULT '{}'::jsonb;
    `;

    console.log('Tablas inicializadas/verificadas en Neon');
  } catch (err) {
    console.error("Error al inicializar la base de datos:", err);
  }
}
initDB();

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

app.get('/favicon.ico', (req, res) => res.status(204).end());

// Ruta secreta temporal para crear tablas en Neon (ANTES del session middleware)
app.get('/api/setup-db', async (req, res) => {
  try {
    await sql`
      CREATE TABLE IF NOT EXISTS users (
          kinde_id VARCHAR(255) PRIMARY KEY,
          company_name VARCHAR(255),
          monthly_volume INTEGER,
          is_setup_complete BOOLEAN DEFAULT false
      );
    `;
    await sql`
      CREATE TABLE IF NOT EXISTS contacts (
          id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
          kinde_id VARCHAR(255) NOT NULL REFERENCES users(kinde_id) ON DELETE CASCADE,
          name VARCHAR(255) NOT NULL,
          email VARCHAR(255) NOT NULL,
          tags TEXT[],
          custom_fields JSONB DEFAULT '{}'::jsonb,
          status VARCHAR(50) DEFAULT 'active',
          added_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
      );
    `;
    await sql`ALTER TABLE contacts ADD COLUMN IF NOT EXISTS custom_fields JSONB DEFAULT '{}'::jsonb;`;
    await sql`
      CREATE TABLE IF NOT EXISTS campaigns (
          id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
          kinde_id VARCHAR(255) NOT NULL REFERENCES users(kinde_id) ON DELETE CASCADE,
          subject VARCHAR(255) NOT NULL,
          body TEXT NOT NULL,
          target_tags TEXT[],
          total_sent INTEGER DEFAULT 0,
          status VARCHAR(50) DEFAULT 'sent',
          sent_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
      );
    `;
    await sql`
      CREATE TABLE IF NOT EXISTS senders (
          id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
          kinde_id VARCHAR(255) NOT NULL REFERENCES users(kinde_id) ON DELETE CASCADE,
          name VARCHAR(255) NOT NULL,
          email VARCHAR(255) NOT NULL,
          is_verified BOOLEAN DEFAULT true,
          dkim_status BOOLEAN DEFAULT true,
          dmarc_status BOOLEAN DEFAULT true,
          created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
      );
    `;
    await sql`CREATE INDEX IF NOT EXISTS idx_contacts_kinde_id ON contacts(kinde_id);`;
    await sql`CREATE INDEX IF NOT EXISTS idx_campaigns_kinde_id ON campaigns(kinde_id);`;
    await sql`CREATE INDEX IF NOT EXISTS idx_senders_kinde_id ON senders(kinde_id);`;
    
    // Tabla de sesiones para connect-pg-simple
    await sql`
      CREATE TABLE IF NOT EXISTS "session" (
        "sid" varchar NOT NULL COLLATE "default",
        "sess" json NOT NULL,
        "expire" timestamp(6) NOT NULL
      );
    `;
    // PostgreSQL constraints no tienen "IF NOT EXISTS" para alterar constraints fácilmente, 
    // pero si la tabla se acaba de crear, podemos tratar de agregarlo. Para ser seguros, capturamos el error si ya existe.
    try {
      await sql`ALTER TABLE "session" ADD CONSTRAINT "session_pkey" PRIMARY KEY ("sid") NOT DEFERRABLE INITIALLY IMMEDIATE;`;
    } catch(e) {}
    await sql`CREATE INDEX IF NOT EXISTS "IDX_session_expire" ON "session" ("expire");`;
    
    res.json({ success: true, message: '¡Tablas creadas exitosamente en Neon!' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Configuración de caché para evitar que Vercel Edge Cache responda con 401 cacheados
app.use('/api', (req, res, next) => {
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('Expires', '0');
  res.setHeader('Surrogate-Control', 'no-store');
  next();
});

// ================= AUTH (KINDE SSO MANUAL JWT) =================
const KINDE_ISSUER_URL = process.env.KINDE_ISSUER_URL || '';
const KINDE_CLIENT_ID = process.env.KINDE_CLIENT_ID || '';
const KINDE_CLIENT_SECRET = process.env.KINDE_CLIENT_SECRET || '';
const KINDE_SITE_URL = process.env.KINDE_SITE_URL || 'http://localhost:3000';
const JWT_SECRET = process.env.JWT_SECRET || process.env.SESSION_SECRET || 'konsul-super-secret-key-123';

app.get('/api/auth/login', (req, res) => {
  const state = crypto.randomBytes(16).toString('hex');
  const baseUrl = KINDE_SITE_URL.replace(/\/$/, '');
  
  const authUrl = `${KINDE_ISSUER_URL}/oauth2/auth?` + new URLSearchParams({
    client_id: KINDE_CLIENT_ID,
    response_type: 'code',
    redirect_uri: `${baseUrl}/api/auth/kinde_callback`,
    scope: 'openid profile email',
    state: state
  });
  res.redirect(authUrl);
});

app.get('/api/auth/kinde_callback', async (req, res) => {
  const { code } = req.query;
  try {
    const baseUrl = KINDE_SITE_URL.replace(/\/$/, '');
    const issuerUrl = KINDE_ISSUER_URL.replace(/\/$/, '');
    const redirectUri = `${baseUrl}/api/auth/kinde_callback`;

    // 1. Intercambiar code por access_token
    const tokenResponse = await fetch(`${issuerUrl}/oauth2/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        client_id: KINDE_CLIENT_ID,
        client_secret: KINDE_CLIENT_SECRET,
        code: code,
        redirect_uri: redirectUri
      })
    });
    const tokenData = await tokenResponse.json();
    if (!tokenData.access_token) {
      console.error("Error from Kinde token endpoint:", tokenData);
      throw new Error(`Kinde Auth Error: ${tokenData.error_description || tokenData.error || 'Unknown'}`);
    }

    // 2. Obtener perfil del usuario
    const profileResponse = await fetch(`${issuerUrl}/oauth2/v2/user_profile`, {
      headers: { Authorization: `Bearer ${tokenData.access_token}` }
    });
    const profile = await profileResponse.json();
    if (!profile.id) {
      console.error("Error fetching Kinde profile:", profile);
      throw new Error("Could not fetch user profile from Kinde");
    }

    // 3. Crear usuario en Neon DB local
    const name = profile.given_name || 'Kônsul User';
    try {
      await sql`
        INSERT INTO users (kinde_id, company_name, monthly_volume, is_setup_complete) 
        VALUES (${profile.id}, ${name}, 10000, true)
        ON CONFLICT (kinde_id) DO NOTHING
      `;
    } catch (dbErr) {
      console.error("Error insertando usuario en Neon DB. ¿Se ejecutó /api/setup-db?", dbErr);
      throw new Error("Database insert failed. Run /api/setup-db first.");
    }

    // 4. Firmar JWT propio
    const token = jwt.sign({ 
      id: profile.id, 
      email: profile.email || profile.preferred_email,
      given_name: profile.given_name 
    }, JWT_SECRET, { expiresIn: '30d' });

    // 5. Redirigir al frontend con el token
    res.redirect(`${baseUrl}/?token=${encodeURIComponent(token)}`);
  } catch (err) {
    console.error("Error en Kinde Callback Manual:", err);
    // Para depurar, enviamos el mensaje de error codificado al frontend
    res.redirect(`/?error=auth_failed&msg=${encodeURIComponent(err.message)}`);
  }
});

app.get('/api/auth/logout', (req, res) => {
  const logoutRedirect = process.env.KINDE_POST_LOGOUT_REDIRECT_URL || KINDE_SITE_URL;
  const logoutUrl = `${KINDE_ISSUER_URL}/logout?redirect=${encodeURIComponent(logoutRedirect)}`;
  res.redirect(logoutUrl);
});

// Middleware de Protección Multi-Tenant con JWT
const protectRoute = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    if (authHeader && authHeader.startsWith('Bearer ')) {
      const token = authHeader.split(' ')[1];
      const decoded = jwt.verify(token, JWT_SECRET);
      req.user = decoded;
      return next();
    }
  } catch (e) {}
  res.status(401).json({ success: false, message: 'No autorizado. Inicia sesión en Kônsul.' });
};

app.get('/api/auth/me', protectRoute, (req, res) => {
  res.json({ authenticated: true, user: req.user });
});

// ================= API ENDPOINTS =================

// 1. Onboarding
app.get('/api/onboarding', protectRoute, async (req, res) => {
  try {
    const userId = req.user.id;
    const result = await sql`SELECT * FROM users WHERE kinde_id = ${userId}`;
    if (result.length > 0) {
      res.json({
        completed: result[0].is_setup_complete,
        companyName: result[0].company_name,
        monthlyVolume: result[0].monthly_volume
      });
    } else {
      res.json({ completed: false, companyName: '', monthlyVolume: 10000 });
    }
  } catch (err) {
    res.status(500).json({ error: 'DB Error' });
  }
});

app.post('/api/onboarding', protectRoute, async (req, res) => {
  try {
    const { companyName, monthlyVolume } = req.body;
    const userId = req.user.id;
    const vol = parseInt(monthlyVolume, 10) || 10000;
    const comp = companyName || 'Kônsul User';
    
    await sql`
      INSERT INTO users (kinde_id, company_name, monthly_volume, is_setup_complete) 
      VALUES (${userId}, ${comp}, ${vol}, true)
      ON CONFLICT (kinde_id) DO UPDATE SET 
        company_name = EXCLUDED.company_name,
        monthly_volume = EXCLUDED.monthly_volume,
        is_setup_complete = EXCLUDED.is_setup_complete
    `;
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'DB Error' });
  }
});

// 2. Contactos
app.get('/api/contacts', protectRoute, async (req, res) => {
  try {
    const userId = req.user.id;
    const contacts = await sql`SELECT * FROM contacts WHERE kinde_id = ${userId} ORDER BY added_at DESC`;
    res.json(contacts.map(c => ({
      id: c.id,
      name: c.name,
      email: c.email,
      tags: c.tags,
      status: c.status,
      dateAdded: c.added_at
    })));
  } catch (err) {
    res.status(500).json({ error: 'DB Error' });
  }
});

app.post('/api/contacts', protectRoute, async (req, res) => {
  try {
    const { name, email, tags, custom_fields } = req.body;
    if (!email || !isValidEmail(email)) return res.status(400).json({ success: false, message: 'Correo no válido.' });
    
    const userId = req.user.id;
    const cleanEmail = email.trim().toLowerCase();
    const contactTags = tags || ['Importados'];

    const existing = await sql`SELECT * FROM contacts WHERE kinde_id = ${userId} AND email = ${cleanEmail}`;
    
    if (existing.length > 0) {
      // Re-suscribir y actualizar
      const mergedTags = [...new Set([...(existing[0].tags || []), ...contactTags])];
      const newName = name || existing[0].name;
      
      await sql`
        UPDATE contacts 
        SET status = 'active', name = ${newName}, tags = ${mergedTags},
            custom_fields = custom_fields || ${JSON.stringify(custom_fields || {})}::jsonb
        WHERE id = ${existing[0].id}
      `;
      return res.json({ success: true, message: 'Contacto actualizado/re-suscrito.' });
    }

    const inserted = await sql`
      INSERT INTO contacts (kinde_id, name, email, tags, custom_fields, status)
      VALUES (${userId}, ${name || 'Suscriptor'}, ${cleanEmail}, ${contactTags}, ${JSON.stringify(custom_fields || {})}::jsonb, 'active')
      RETURNING *
    `;
    
    res.json({ success: true, contact: inserted[0] });
  } catch (err) {
    console.error('Error insertando contacto:', err);
    res.status(500).json({ error: 'DB Error', message: err.message || String(err) });
  }
});

app.post('/api/contacts/bulk', protectRoute, async (req, res) => {
  try {
    const { list } = req.body;
    if (!Array.isArray(list)) return res.status(400).json({ success: false, message: 'Debe ser un array.' });

    const userId = req.user.id;
    let added = 0;

    for (const item of list) {
      let email = typeof item === 'string' ? item : item.email;
      let name = typeof item === 'string' ? 'Suscriptor' : (item.name || 'Suscriptor');
      let tags = typeof item === 'string' ? ['Importados'] : (item.tags || ['Importados']);

      let custom_fields = typeof item === 'string' ? {} : (item.custom_fields || {});

      if (email && isValidEmail(email)) {
        email = email.trim().toLowerCase();
        
        const existing = await sql`SELECT id, status FROM contacts WHERE kinde_id = ${userId} AND email = ${email}`;
        
        if (existing.length === 0) {
          await sql`
            INSERT INTO contacts (kinde_id, name, email, tags, custom_fields, status)
            VALUES (${userId}, ${name}, ${email}, ${tags}, ${JSON.stringify(custom_fields)}::jsonb, 'active')
          `;
          added++;
        } else {
          // Si el contacto ya existe, actualizamos sus custom_fields de forma segura
          await sql`
            UPDATE contacts 
            SET 
              custom_fields = custom_fields || ${JSON.stringify(custom_fields)}::jsonb,
              status = CASE WHEN status = 'unsubscribe' THEN 'active' ELSE status END
            WHERE id = ${existing[0].id}
          `;
          added++;
        }
      }
    }

    res.json({ success: true, added });
  } catch (err) {
    console.error('Error en bulk insert:', err);
    res.status(500).json({ error: 'DB Error', message: err.message || String(err), stack: err.stack });
  }
});

app.delete('/api/contacts/:id', protectRoute, async (req, res) => {
  try {
    const userId = req.user.id;
    const result = await sql`DELETE FROM contacts WHERE kinde_id = ${userId} AND id = ${req.params.id}`;
    if (result.count === 0) return res.status(404).json({ success: false, message: 'No encontrado.' });
    res.json({ success: true, message: 'Eliminado correctamente.' });
  } catch (err) {
    res.status(500).json({ error: 'DB Error' });
  }
});

app.post('/api/contacts/delete-bulk', protectRoute, async (req, res) => {
  try {
    const userId = req.user.id;
    const { ids } = req.body;
    if (!Array.isArray(ids) || ids.length === 0) {
      return res.status(400).json({ success: false, message: 'Se requiere una lista de IDs válida.' });
    }
    
    await sql`
      DELETE FROM contacts 
      WHERE kinde_id = ${userId} AND id = ANY(${ids})
    `;
    res.json({ success: true, message: 'Contactos eliminados correctamente.' });
  } catch (err) {
    console.error('Error delete bulk:', err);
    res.status(500).json({ success: false, error: 'DB Error' });
  }
});

app.post('/api/contacts/delete-by-tag', protectRoute, async (req, res) => {
  try {
    const userId = req.user.id;
    const { tag } = req.body;
    if (!tag) {
      return res.status(400).json({ success: false, message: 'Se requiere una etiqueta.' });
    }
    
    await sql`
      DELETE FROM contacts 
      WHERE kinde_id = ${userId} AND ${tag} = ANY(tags)
    `;
    res.json({ success: true, message: `Contactos de la lista '${tag}' eliminados correctamente.` });
  } catch (err) {
    console.error('Error delete by tag:', err);
    res.status(500).json({ success: false, error: 'DB Error' });
  }
});

app.post('/api/contacts/rename-tag', protectRoute, async (req, res) => {
  try {
    const userId = req.user.id;
    const { oldTag, newTag } = req.body;
    if (!oldTag || !newTag) {
      return res.status(400).json({ success: false, message: 'Se requiere nombre antiguo y nuevo.' });
    }

    await sql`
      UPDATE contacts 
      SET tags = array_replace(tags, ${oldTag}, ${newTag})
      WHERE kinde_id = ${userId} AND ${oldTag} = ANY(tags)
    `;
    res.json({ success: true, message: `Lista renombrada correctamente a '${newTag}'.` });
  } catch (err) {
    console.error('Error rename tag:', err);
    res.status(500).json({ success: false, error: 'DB Error' });
  }
});

// Remitentes (Senders)
app.get('/api/senders', protectRoute, async (req, res) => {
  try {
    const userId = req.user.id;
    const senders = await sql`SELECT * FROM senders WHERE kinde_id = ${userId} ORDER BY created_at DESC`;
    res.json(senders);
  } catch (err) {
    res.status(500).json({ error: 'DB Error' });
  }
});

app.post('/api/senders', protectRoute, async (req, res) => {
  try {
    const userId = req.user.id;
    const { name, email } = req.body;
    
    if (!name || !email) {
      return res.status(400).json({ success: false, message: 'Faltan campos' });
    }

    const inserted = await sql`
      INSERT INTO senders (kinde_id, name, email)
      VALUES (${userId}, ${name}, ${email})
      RETURNING *
    `;
    res.json({ success: true, sender: inserted[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, error: 'DB Error' });
  }
});

app.delete('/api/senders/:id', protectRoute, async (req, res) => {
  try {
    const userId = req.user.id;
    const { id } = req.params;
    await sql`DELETE FROM senders WHERE id = ${id} AND kinde_id = ${userId}`;
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, error: 'DB Error' });
  }
});

// ======================== DOMAINS ========================
const sesClient = new SESClient({ region: process.env.AWS_REGION || 'us-east-1' });

app.get('/api/domains', protectRoute, async (req, res) => {
  try {
    const userId = req.user.id;
    const domains = await sql`SELECT * FROM domains WHERE kinde_id = ${userId} ORDER BY created_at DESC`;
    
    // Check status in AWS SES for pending domains
    const updatedDomains = [];
    for (let dom of domains) {
      if (dom.verification_status !== 'Success' || dom.dkim_status !== 'Success') {
        try {
          const vCmd = new GetIdentityVerificationAttributesCommand({ Identities: [dom.domain_name] });
          const vRes = await sesClient.send(vCmd);
          const vStatus = vRes.VerificationAttributes?.[dom.domain_name]?.VerificationStatus || dom.verification_status;
          
          const dCmd = new GetIdentityDkimAttributesCommand({ Identities: [dom.domain_name] });
          const dRes = await sesClient.send(dCmd);
          const dStatus = dRes.DkimAttributes?.[dom.domain_name]?.DkimVerificationStatus || dom.dkim_status;
          
          if (vStatus !== dom.verification_status || dStatus !== dom.dkim_status) {
            const updated = await sql`UPDATE domains SET verification_status = ${vStatus}, dkim_status = ${dStatus} WHERE id = ${dom.id} RETURNING *`;
            updatedDomains.push(updated[0]);
            continue;
          }
        } catch(e) {
          console.error("SES status check failed for", dom.domain_name, e);
        }
      }
      updatedDomains.push(dom);
    }
    res.json(updatedDomains);
  } catch (err) {
    res.status(500).json({ error: 'DB Error' });
  }
});

app.post('/api/domains', protectRoute, async (req, res) => {
  try {
    const userId = req.user.id;
    const { domain_name } = req.body;
    
    if (!domain_name) return res.status(400).json({ success: false, message: 'Falta nombre de dominio' });
    
    const vCmd = new VerifyDomainIdentityCommand({ Domain: domain_name });
    await sesClient.send(vCmd);
    
    const dCmd = new VerifyDomainDkimCommand({ Domain: domain_name });
    const dRes = await sesClient.send(dCmd);
    const tokens = dRes.DkimTokens || [];
    
    const inserted = await sql`
      INSERT INTO domains (kinde_id, domain_name, dkim_tokens)
      VALUES (${userId}, ${domain_name}, ${tokens})
      RETURNING *
    `;
    res.json({ success: true, domain: inserted[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: err.message || 'SES/DB Error' });
  }
});

app.delete('/api/domains/:id', protectRoute, async (req, res) => {
  try {
    const userId = req.user.id;
    const { id } = req.params;
    await sql`DELETE FROM domains WHERE id = ${id} AND kinde_id = ${userId}`;
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ success: false, error: 'DB Error' });
  }
});

// ======================== DEDICATED IPs ========================
app.get('/api/ips', protectRoute, async (req, res) => {
  try {
    const userId = req.user.id;
    const ips = await sql`SELECT * FROM dedicated_ips WHERE kinde_id = ${userId} ORDER BY requested_at DESC`;
    res.json(ips);
  } catch (err) {
    res.status(500).json({ error: 'DB Error' });
  }
});

app.post('/api/ips', protectRoute, async (req, res) => {
  try {
    const userId = req.user.id;
    const inserted = await sql`
      INSERT INTO dedicated_ips (kinde_id)
      VALUES (${userId})
      RETURNING *
    `;
    res.json({ success: true, ip: inserted[0] });
  } catch (err) {
    res.status(500).json({ success: false, error: 'DB Error' });
  }
});

// ======================== CADENCE ========================
app.get('/api/settings/cadence', protectRoute, async (req, res) => {
  try {
    const userId = req.user.id;
    const result = await sql`SELECT hourly_limit, warmup_mode FROM users WHERE kinde_id = ${userId}`;
    res.json(result[0] || { hourly_limit: 1000, warmup_mode: false });
  } catch (err) {
    res.status(500).json({ error: 'DB Error' });
  }
});

app.post('/api/settings/cadence', protectRoute, async (req, res) => {
  try {
    const userId = req.user.id;
    const { hourly_limit, warmup_mode } = req.body;
    await sql`UPDATE users SET hourly_limit = ${hourly_limit}, warmup_mode = ${warmup_mode} WHERE kinde_id = ${userId}`;
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ success: false, error: 'DB Error' });
  }
});

// 3. Campañas y Envío
app.get('/api/campaigns', protectRoute, async (req, res) => {
  try {
    const userId = req.user.id;
    const campaigns = await sql`SELECT * FROM campaigns WHERE kinde_id = ${userId} ORDER BY sent_at DESC`;
    res.json(campaigns.map(c => ({
      id: c.id,
      subject: c.subject,
      body: c.body,
      targetTags: c.target_tags,
      totalSent: c.total_sent,
      status: c.status,
      sentDate: c.sent_at,
      opens: 0,
      clicks: 0
    })));
  } catch (err) {
    res.status(500).json({ error: 'DB Error' });
  }
});

app.post('/api/send-bulk', protectRoute, async (req, res) => {
  try {
    const { subject, body, recipients, limit, targetTags } = req.body;
    const userId = req.user.id;

    if (!subject || !body || !recipients || !Array.isArray(recipients)) {
      return res.status(400).json({ success: false, message: 'Faltan datos.' });
    }

    const cleanRecipients = [...new Set(recipients.map(e => e.trim().toLowerCase()).filter(isValidEmail))];

    // Filter active recipients from DB
    const activeContacts = await sql`
      SELECT email FROM contacts 
      WHERE kinde_id = ${userId} AND status != 'unsubscribe' 
      AND email = ANY(${cleanRecipients})
    `;
    const activeEmails = activeContacts.map(c => c.email);

    if (activeEmails.length === 0) {
      return res.status(400).json({ success: false, message: 'No hay destinatarios válidos activos.' });
    }

    const allowedLimit = parseInt(limit, 10) || 10000;
    if (activeEmails.length > allowedLimit) {
      return res.status(400).json({ success: false, message: `Supera límite de ${allowedLimit}.` });
    }

    // Configurar AWS SES
    const hasAwsCreds = !!process.env.SES_SENDER_EMAIL;
    let sesClient = null;
    let senderEmail = process.env.SES_SENDER_EMAIL;

    if (hasAwsCreds) {
      sesClient = new SESClient({ region: process.env.AWS_REGION || 'us-east-1' });
    }

    const successes = [];
    const failures = [];

    // Registrar campaña
    const campaignInsert = await sql`
      INSERT INTO campaigns (kinde_id, subject, body, target_tags, total_sent, status)
      VALUES (${userId}, ${subject}, ${body}, ${targetTags || []}, ${activeEmails.length}, 'sending')
      RETURNING id
    `;
    const campaignId = campaignInsert[0].id;

    for (let i = 0; i < activeEmails.length; i++) {
      const recipient = activeEmails[i];
      const unsubscribeUrl = `https://${req.get('host')}/unsubscribe/${campaignId}/${encodeURIComponent(recipient)}`;
      const openTrackingUrl = `https://${req.get('host')}/api/campaigns/${campaignId}/track-open?email=${encodeURIComponent(recipient)}`;
      
      const richBody = `
        <div style="font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif; color: #1B2939; padding: 20px; max-width: 600px; margin: 0 auto; background-color: #FAF8F5; border-radius: 16px;">
          ${body}
          <hr style="border: 0; border-top: 1px solid #EAE6DF; margin: 30px 0;" />
          <div style="font-size: 11px; color: #6E7A8A; text-align: center;">
            <p>Has recibido este correo de parte de tu suscripción en la Suite Kônsul.</p>
            <p><a href="${unsubscribeUrl}" style="color: #27bea7; text-decoration: underline;">Darme de baja de esta lista</a></p>
          </div>
          <img src="${openTrackingUrl}" width="1" height="1" style="display:none;" />
        </div>
      `;

      try {
        if (hasAwsCreds && sesClient) {
          const command = new SendEmailCommand({
            Source: senderEmail,
            Destination: { ToAddresses: [recipient] },
            Message: {
              Subject: { Data: subject, Charset: 'UTF-8' },
              Body: { Html: { Data: richBody, Charset: 'UTF-8' } }
            }
          });
          await sesClient.send(command);
        } else {
          await sleep(60); 
        }
        successes.push(recipient);
      } catch (err) {
        failures.push({ email: recipient, error: err.message });
      }

      if (i < activeEmails.length - 1) await sleep(95);
    }

    // Actualizar estado de campaña
    await sql`UPDATE campaigns SET status = 'sent' WHERE id = ${campaignId}`;

    res.json({
      success: true,
      simulation: !hasAwsCreds,
      campaignId,
      total: activeEmails.length,
      sentCount: successes.length,
      failedCount: failures.length,
      failures
    });

  } catch (error) {
    res.status(500).json({ success: false, message: 'Error procesando campaña.' });
  }
});

// 4. Tracking & Unsubscribe
app.get('/api/campaigns/:id/track-open', async (req, res) => {
  const pixel = Buffer.from('R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7', 'base64');
  res.writeHead(200, {
    'Content-Type': 'image/gif',
    'Content-Length': pixel.length,
    'Cache-Control': 'no-store, no-cache, must-revalidate, private'
  });
  res.end(pixel);
});

// Ruta pública de Desuscripción con Campaign ID para saber el Tenant
app.get('/unsubscribe/:campaignId/:email', async (req, res) => {
  try {
    const { campaignId, email } = req.params;
    const cleanEmail = decodeURIComponent(email).toLowerCase();
    
    // Buscar la campaña para obtener el kinde_id
    const campaignData = await sql`SELECT kinde_id FROM campaigns WHERE id = ${campaignId}`;
    
    if (campaignData.length > 0) {
      const userId = campaignData[0].kinde_id;
      await sql`UPDATE contacts SET status = 'unsubscribe' WHERE kinde_id = ${userId} AND email = ${cleanEmail}`;
    }

    res.send(`
      <!DOCTYPE html>
      <html lang="es">
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Suscripción Cancelada | Kônsul</title>
        <script src="https://cdn.tailwindcss.com"></script>
        <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;600&display=swap" rel="stylesheet">
        <style> body { font-family: 'Outfit', sans-serif; background-color: #FAF8F5; } </style>
      </head>
      <body class="min-h-screen flex items-center justify-center p-6 text-[#1B2939]">
        <div class="max-w-md w-full bg-white border border-[#EAE6DF] rounded-3xl p-8 text-center shadow-sm">
          <div class="text-4xl mb-4">🍃</div>
          <h1 class="text-2xl font-bold mb-2">Suscripción cancelada</h1>
          <p class="text-sm text-[#6E7A8A] mb-6">Hemos removido a <strong>${cleanEmail}</strong> de nuestra lista.</p>
        </div>
      </body>
      </html>
    `);
  } catch (err) {
    res.status(500).send("Error procesando baja.");
  }
});

// Fallback para el frontend (SPA)
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

if (!process.env.VERCEL) {
  app.listen(PORT, () => {
    console.log(`🚀 Servidor Kônsul en http://localhost:${PORT}`);
  });
}

module.exports = app;

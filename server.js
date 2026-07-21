const express = require('express');
const cors = require('cors');
const path = require('path');
const session = require('express-session');
const pgSession = require('connect-pg-simple')(session);
const { KindeClient, GrantType } = require('@kinde-oss/kinde-nodejs-sdk');
const { SESClient, SendEmailCommand } = require('@aws-sdk/client-ses');
const { neon } = require('@neondatabase/serverless');
const { Pool } = require('pg');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// Configurar base de datos Neon
const dbUrl = process.env.DATABASE_URL || 'postgresql://user:pass@ep-host.neon.tech/db?sslmode=require';
const sql = neon(dbUrl);
const pool = new Pool({ connectionString: dbUrl });

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

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
    await sql`CREATE INDEX IF NOT EXISTS idx_contacts_kinde_id ON contacts(kinde_id);`;
    await sql`CREATE INDEX IF NOT EXISTS idx_campaigns_kinde_id ON campaigns(kinde_id);`;
    
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

// Session Middleware
app.set('trust proxy', 1); // Trust Vercel's proxy for secure cookies
app.use(session({
  store: new pgSession({
    pool: pool,
    tableName: 'session'
  }),
  secret: process.env.SESSION_SECRET || 'konsul-super-secret-key-123',
  resave: false,
  saveUninitialized: false, // Better false for authenticated sessions
  cookie: {
    maxAge: 30 * 24 * 60 * 60 * 1000,
    secure: process.env.VERCEL ? true : false,
    sameSite: 'lax'
  }
}));

// Configurar Cliente Kinde
const options = {
  domain: process.env.KINDE_ISSUER_URL || '',
  clientId: process.env.KINDE_CLIENT_ID || '',
  clientSecret: process.env.KINDE_CLIENT_SECRET || '',
  redirectUri: (process.env.KINDE_SITE_URL || 'http://localhost:3000') + '/api/auth/kinde_callback',
  logoutRedirectUri: process.env.KINDE_POST_LOGOUT_REDIRECT_URL || process.env.KINDE_SITE_URL || 'http://localhost:3000',
  grantType: GrantType.AUTHORIZATION_CODE
};
const kindeClient = new KindeClient(options);

// Función auxiliar para delay (control del rate limit de SES)
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

// Helper para validar email
const isValidEmail = (email) => {
  const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return re.test(String(email).toLowerCase().trim());
};

// ================= AUTH (KINDE SSO) =================
app.get('/api/auth/login', async (req, res) => {
  try {
    const prompt = req.query.prompt;
    const loginUrl = await kindeClient.login(req, prompt ? { prompt } : {});
    res.redirect(loginUrl);
  } catch (err) {
    console.error("Error en login Kinde:", err);
    res.redirect('/?error=auth_failed');
  }
});

app.get('/api/auth/kinde_callback', async (req, res) => {
  try {
    await kindeClient.getToken(req);
    // En Serverless (Vercel), se debe esperar explícitamente a que req.session.save() complete la inserción en DB
    if (req.session) {
      await new Promise((resolve, reject) => {
        req.session.save((err) => {
          if (err) return reject(err);
          resolve();
        });
      });
    }
    res.redirect('/');
  } catch (err) {
    console.error("Error en Kinde Callback:", err);
    res.redirect('/?error=auth_failed');
  }
});

app.get('/api/auth/logout', async (req, res) => {
  try {
    const logoutUrl = await kindeClient.logout(req);
    if (req.session) {
      await new Promise((resolve) => req.session.destroy(() => resolve()));
    }
    res.redirect(logoutUrl);
  } catch (err) {
    res.redirect('/');
  }
});

app.get('/api/auth/me', async (req, res) => {
  try {
    const isAuth = await kindeClient.isAuthenticated(req);
    if (!isAuth) return res.status(401).json({ authenticated: false });
    const user = await kindeClient.getUserProfile(req);
    res.json({ authenticated: true, user });
  } catch (err) {
    res.status(401).json({ authenticated: false });
  }
});

// Middleware de Protección Multi-Tenant
const protectRoute = async (req, res, next) => {
  try {
    if (await kindeClient.isAuthenticated(req)) {
      req.user = await kindeClient.getUserProfile(req);
      return next();
    }
  } catch (e) {}
  res.status(401).json({ success: false, message: 'No autorizado. Inicia sesión en Kônsul.' });
};

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
    const { name, email, tags } = req.body;
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
        SET status = 'active', name = ${newName}, tags = ${mergedTags}
        WHERE id = ${existing[0].id}
      `;
      return res.json({ success: true, message: 'Contacto actualizado/re-suscrito.' });
    }

    const inserted = await sql`
      INSERT INTO contacts (kinde_id, name, email, tags, status)
      VALUES (${userId}, ${name || 'Suscriptor'}, ${cleanEmail}, ${contactTags}, 'active')
      RETURNING *
    `;
    
    res.json({ success: true, contact: inserted[0] });
  } catch (err) {
    res.status(500).json({ error: 'DB Error' });
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

      if (email && isValidEmail(email)) {
        email = email.trim().toLowerCase();
        
        const existing = await sql`SELECT id, status FROM contacts WHERE kinde_id = ${userId} AND email = ${email}`;
        
        if (existing.length === 0) {
          await sql`
            INSERT INTO contacts (kinde_id, name, email, tags, status)
            VALUES (${userId}, ${name}, ${email}, ${tags}, 'active')
          `;
          added++;
        } else if (existing[0].status === 'unsubscribe') {
          await sql`UPDATE contacts SET status = 'active' WHERE id = ${existing[0].id}`;
          added++;
        }
      }
    }

    res.json({ success: true, added });
  } catch (err) {
    res.status(500).json({ error: 'DB Error' });
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

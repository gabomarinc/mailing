const express = require('express');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const session = require('express-session');
const { KindeClient, GrantType } = require('@kinde-oss/kinde-nodejs-sdk');
const { SESClient, SendEmailCommand } = require('@aws-sdk/client-ses');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;
// En Vercel el sistema de archivos es de solo lectura excepto /tmp
const DB_PATH = process.env.VERCEL ? path.join('/tmp', 'data.json') : path.join(__dirname, 'data.json');

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Session Middleware
app.use(session({
  secret: process.env.SESSION_SECRET || 'konsul-super-secret-key-123',
  resave: false,
  saveUninitialized: true,
  cookie: { secure: process.env.VERCEL ? true : false }
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

// Helper: Leer Base de Datos
const readDB = () => {
  try {
    if (!fs.existsSync(DB_PATH)) {
      return { onboarding: { completed: false, companyName: '', monthlyVolume: 10000 }, contacts: [], campaigns: [] };
    }
    const data = fs.readFileSync(DB_PATH, 'utf-8');
    return JSON.parse(data);
  } catch (error) {
    console.error('Error leyendo base de datos:', error);
    return { onboarding: { completed: false, companyName: '', monthlyVolume: 10000 }, contacts: [], campaigns: [] };
  }
};

// Helper: Escribir en la Base de Datos
const writeDB = (data) => {
  try {
    fs.writeFileSync(DB_PATH, JSON.stringify(data, null, 2), 'utf-8');
    return true;
  } catch (error) {
    console.error('Error escribiendo en base de datos:', error);
    return false;
  }
};

// Función auxiliar para delay (control del rate limit de SES)
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

// Helper para validar email
const isValidEmail = (email) => {
  const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return re.test(String(email).toLowerCase().trim());
};

// ================= AUTH (KINDE SSO) =================
app.get('/api/auth/login', async (req, res) => {
  const prompt = req.query.prompt;
  const loginUrl = await kindeClient.login(req, prompt ? { prompt } : {});
  res.redirect(loginUrl);
});

app.get('/api/auth/kinde_callback', async (req, res) => {
  try {
    await kindeClient.getToken(req);
    res.redirect('/');
  } catch (err) {
    console.error("Error en Kinde Callback:", err);
    res.redirect('/?error=auth_failed');
  }
});

app.get('/api/auth/logout', async (req, res) => {
  const logoutUrl = await kindeClient.logout(req);
  res.redirect(logoutUrl);
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

// Middleware de Protección
const protectRoute = async (req, res, next) => {
  try {
    if (await kindeClient.isAuthenticated(req)) {
      return next();
    }
  } catch (e) {}
  res.status(401).json({ success: false, message: 'No autorizado. Inicia sesión en Kônsul.' });
};

// ================= API ENDPOINTS =================

// 1. Onboarding
app.get('/api/onboarding', protectRoute, (req, res) => {
  const db = readDB();
  res.json(db.onboarding);
});

app.post('/api/onboarding', protectRoute, (req, res) => {
  const { companyName, monthlyVolume } = req.body;
  const db = readDB();
  
  db.onboarding = {
    completed: true,
    companyName: companyName || 'Kônsul User',
    monthlyVolume: parseInt(monthlyVolume, 10) || 10000
  };
  
  writeDB(db);
  res.json({ success: true, onboarding: db.onboarding });
});

// 2. Contactos
app.get('/api/contacts', protectRoute, (req, res) => {
  const db = readDB();
  res.json(db.contacts);
});

app.post('/api/contacts', protectRoute, (req, res) => {
  const { name, email, tags } = req.body;
  
  if (!email || !isValidEmail(email)) {
    return res.status(400).json({ success: false, message: 'Correo electrónico no válido.' });
  }

  const db = readDB();
  
  // Evitar duplicados
  const existing = db.contacts.find(c => c.email.toLowerCase() === email.toLowerCase());
  if (existing) {
    // Si ya existe pero estaba de baja, lo volvemos a activar si es re-suscripción
    existing.status = 'active';
    if (name) existing.name = name;
    if (tags) existing.tags = [...new Set([...existing.tags, ...tags])];
    writeDB(db);
    return res.json({ success: true, contact: existing, message: 'Contacto actualizado/re-suscrito.' });
  }

  const newContact = {
    id: 'c_' + Date.now() + Math.random().toString(36).substr(2, 5),
    name: name || 'Suscriptor',
    email: email.trim().toLowerCase(),
    status: 'active',
    tags: tags || ['Importados'],
    dateAdded: new Date().toISOString()
  };

  db.contacts.push(newContact);
  writeDB(db);

  res.json({ success: true, contact: newContact });
});

// Carga masiva de contactos
app.post('/api/contacts/bulk', protectRoute, (req, res) => {
  const { list } = req.body; // Array de { name, email, tags } o simplemente emails
  if (!Array.isArray(list)) {
    return res.status(400).json({ success: false, message: 'La lista debe ser un array.' });
  }

  const db = readDB();
  let added = 0;

  list.forEach(item => {
    let email = typeof item === 'string' ? item : item.email;
    let name = typeof item === 'string' ? 'Suscriptor' : (item.name || 'Suscriptor');
    let tags = typeof item === 'string' ? ['Importados'] : (item.tags || ['Importados']);

    if (email && isValidEmail(email)) {
      email = email.trim().toLowerCase();
      const existing = db.contacts.find(c => c.email.toLowerCase() === email);
      if (!existing) {
        db.contacts.push({
          id: 'c_' + Date.now() + Math.random().toString(36).substr(2, 5),
          name,
          email,
          status: 'active',
          tags,
          dateAdded: new Date().toISOString()
        });
        added++;
      } else if (existing.status === 'unsubscribe') {
        existing.status = 'active'; // Lo reactivamos
        added++;
      }
    }
  });

  writeDB(db);
  res.json({ success: true, added, total: db.contacts.length });
});

// Eliminar contacto
app.delete('/api/contacts/:id', protectRoute, (req, res) => {
  const db = readDB();
  const initialLength = db.contacts.length;
  db.contacts = db.contacts.filter(c => c.id !== req.params.id);
  
  if (db.contacts.length === initialLength) {
    return res.status(404).json({ success: false, message: 'Contacto no encontrado.' });
  }
  
  writeDB(db);
  res.json({ success: true, message: 'Contacto eliminado correctamente.' });
});

// 3. Campañas y Envío
app.get('/api/campaigns', protectRoute, (req, res) => {
  const db = readDB();
  res.json(db.campaigns);
});

// Envío de campaña
app.post('/api/send-bulk', protectRoute, async (req, res) => {
  try {
    const { subject, body, recipients, limit, targetTags } = req.body;

    if (!subject || !body || !recipients || !Array.isArray(recipients)) {
      return res.status(400).json({
        success: false,
        message: 'Por favor, proporciona un asunto, cuerpo y una lista de destinatarios.'
      });
    }

    const db = readDB();
    const cleanRecipients = [...new Set(recipients
      .map(email => email.trim().toLowerCase())
      .filter(email => email !== '' && isValidEmail(email)))
    ];

    // Filtrar destinatarios que estén de baja
    const activeRecipients = cleanRecipients.filter(email => {
      const contact = db.contacts.find(c => c.email.toLowerCase() === email);
      return !contact || contact.status !== 'unsubscribe';
    });

    if (activeRecipients.length === 0) {
      return res.status(400).json({
        success: false,
        message: 'No hay destinatarios válidos activos para enviar (algunos pueden estar dados de baja).'
      });
    }

    const allowedLimit = parseInt(limit, 10) || 10000;
    if (activeRecipients.length > allowedLimit) {
      return res.status(400).json({
        success: false,
        message: `El número de destinatarios (${activeRecipients.length}) supera el límite configurado (${allowedLimit} correos).`
      });
    }

    // Configuración de AWS
    const hasAwsCreds = !!process.env.SES_SENDER_EMAIL;
    let sesClient = null;
    let senderEmail = process.env.SES_SENDER_EMAIL;

    if (hasAwsCreds) {
      sesClient = new SESClient({
        region: process.env.AWS_REGION || 'us-east-1'
      });
    }

    const campaignId = 'camp_' + Date.now();
    const successes = [];
    const failures = [];

    // Enviar secuencialmente
    for (let i = 0; i < activeRecipients.length; i++) {
      const recipient = activeRecipients[i];
      
      // Enlaces dinámicos de baja y tracking
      const unsubscribeUrl = `http://localhost:${PORT}/unsubscribe/${encodeURIComponent(recipient)}`;
      const openTrackingUrl = `http://localhost:${PORT}/api/campaigns/${campaignId}/track-open?email=${encodeURIComponent(recipient)}`;
      
      // Modificar el body para inyectar tracking de apertura y pie de página de baja
      // Si el cuerpo tiene enlaces href="...", se pueden trackear reescribiendo enlaces en el frontend
      // o agregando un footer con estilo Kônsul
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
          await sleep(60); // Simulación con delay
          if (Math.random() < 0.02) {
            throw new Error('Entrega rechazada temporalmente por el servidor receptor');
          }
        }
        successes.push(recipient);
      } catch (err) {
        failures.push({ email: recipient, error: err.message });
      }

      if (i < activeRecipients.length - 1) {
        await sleep(95); // Rate Limiting de seguridad
      }
    }

    // Registrar campaña en la base de datos
    const newCampaign = {
      id: campaignId,
      subject,
      body,
      sentDate: new Date().toISOString(),
      totalSent: activeRecipients.length,
      successCount: successes.length,
      failedCount: failures.length,
      opens: 0,
      openList: [], // Emails que han abierto
      clicks: 0,
      status: 'sent'
    };

    db.campaigns.push(newCampaign);
    writeDB(db);

    res.json({
      success: true,
      simulation: !hasAwsCreds,
      campaignId,
      total: activeRecipients.length,
      sentCount: successes.length,
      failedCount: failures.length,
      failures
    });

  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: 'Error procesando la campaña masiva.' });
  }
});

// 4. Tracking & Unsubscribe
// Tracking de Aperturas (Píxel transparente de 1x1)
app.get('/api/campaigns/:id/track-open', (req, res) => {
  const { id } = req.params;
  const { email } = req.query;
  
  const db = readDB();
  const campaign = db.campaigns.find(c => c.id === id);
  
  if (campaign && email) {
    if (!campaign.openList) {
      campaign.openList = [];
    }
    if (!campaign.openList.includes(email)) {
      campaign.openList.push(email);
      campaign.opens = campaign.openList.length;
      writeDB(db);
    }
  }

  // Retornar píxel transparente de 1x1 GIF
  const pixel = Buffer.from('R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7', 'base64');
  res.writeHead(200, {
    'Content-Type': 'image/gif',
    'Content-Length': pixel.length,
    'Cache-Control': 'no-store, no-cache, must-revalidate, private'
  });
  res.end(pixel);
});

// Ruta pública de Desuscripción (Unsubscribe)
app.get('/unsubscribe/:email', (req, res) => {
  const { email } = req.params;
  const db = readDB();
  
  const contact = db.contacts.find(c => c.email.toLowerCase() === decodeURIComponent(email).toLowerCase());
  
  if (contact) {
    contact.status = 'unsubscribe';
    writeDB(db);
  }

  // Responder con página HTML de despedida empática
  res.send(`
    <!DOCTYPE html>
    <html lang="es">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>Suscripción Cancelada | Kônsul</title>
      <script src="https://cdn.tailwindcss.com"></script>
      <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;600&display=swap" rel="stylesheet">
      <style>
        body { font-family: 'Outfit', sans-serif; background-color: #FAF8F5; }
      </style>
    </head>
    <body class="min-h-screen flex items-center justify-center p-6 text-[#1B2939]">
      <div class="max-w-md w-full bg-white border border-[#EAE6DF] rounded-3xl p-8 text-center shadow-sm">
        <div class="text-4xl mb-4">🍃</div>
        <h1 class="text-2xl font-bold mb-2">Tu suscripción ha sido cancelada</h1>
        <p class="text-sm text-[#6E7A8A] mb-6">
          Lamentamos verte partir. Hemos removido a <strong>${decodeURIComponent(email)}</strong> de nuestra lista de envíos. No recibirás más correos de esta campaña.
        </p>
        <div class="text-xs text-[#6E7A8A]">
          ¿Fue un error? Si deseas volver a suscribirte en el futuro, puedes contactar al administrador del sitio.
        </div>
      </div>
    </body>
    </html>
  `);
});

// Fallback para el frontend (SPA)
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

if (!process.env.VERCEL) {
  app.listen(PORT, () => {
    console.log(`🚀 Servidor Kônsul Email Marketing en ejecución en http://localhost:${PORT}`);
  });
}

module.exports = app;

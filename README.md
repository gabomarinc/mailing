# Kônsul Mailing

Plataforma de Email Marketing de envío masivo ultra-eficiente de Kônsul Suite, construida con enfoque en Diseño Emocional y orientada a la alta escalabilidad.

## Características Principales

*   **Gestión de Contactos y Listas**: 
    *   Soporte para campos estándar y personalizados (dinámicos).
    *   Importación masiva desde CSV y Excel (`.xlsx`, `.xls`, `.ods`, `.numbers`), con soporte nativo para detección de múltiples hojas (cada hoja puede convertirse en una lista).
    *   Detección automática de columnas (nombre, email) y mapeo interactivo de campos personalizados.
    *   Validación de correos en segundo plano (verificación de sintaxis, dominios desechables y resolución de registros DNS/MX).
*   **Captación de Leads (Formularios)**:
    *   Wizard interactivo de 3 pasos para la creación de formularios.
    *   Múltiples opciones de diseño: Vertical (Clásico), Horizontal (In-line), Minimalista y Glassmorphism.
    *   Previsualización en tiempo real interactiva (Live Preview).
    *   Soporte para campos personalizados dinámicos basados en la lista objetivo.
    *   Opciones de integración: iFrame script dinámico y código HTML estático.
    *   Métricas detalladas por formulario (vistas, conversiones, porcentaje de conversión).
*   **Constructor de Correos (Email Builder)**:
    *   Editor tipo LEGO "Drag and Drop" para el diseño de plantillas responsivas.
    *   Soporte para texto enriquecido, botones, divisores e imágenes (proxy de subida vía Catbox/Imgur).
    *   Etiquetas de personalización dinámicas (`{name}`, etc.).
    *   Gestión centralizada de pie de página (footer) de la empresa y opciones de desuscripción.
*   **Gestión de Campañas**:
    *   Wizard de 3 pasos para configuración, diseño y programación de campañas.
    *   Filtros avanzados de segmentación (por lista/etiqueta, fecha, campos personalizados).
    *   Programación de envío diferido con notificaciones de estado en tiempo real.
    *   Simulación de envío en ausencia de credenciales AWS (para desarrollo).
*   **Reportes y Analíticas Detalladas**:
    *   Métricas de apertura y clics en tiempo real mediante píxel de seguimiento 1x1.
    *   Desglose geográfico y de dispositivos (Desktop, Mobile, Tablet).
    *   Mapa de calor de clics y registro de errores de entrega (bounces).
*   **Infraestructura y Seguridad**:
    *   Autenticación SSO segura utilizando Kinde OAuth 2.0.
    *   Integración robusta con AWS SES para entregabilidad, manejo de bounces y quejas (SNS Webhooks).
    *   Gestión de identidades (remitentes) y autenticación de dominios (DKIM, DMARC) directamente en el panel.
    *   Aceleración dinámica (Warmup Mode) y control de cadencia de envíos por hora.

---

## Tecnologías Utilizadas

*   **Frontend**: HTML5, Vanilla JavaScript, Tailwind CSS (Custom Brand Palette).
*   **Backend**: Node.js, Express.js.
*   **Base de Datos**: PostgreSQL (Neon Serverless).
*   **Autenticación**: Kinde (OAuth 2.0 / JWT).
*   **Envío de Correos**: Amazon Simple Email Service (AWS SES).
*   **Despliegue**: Vercel (Serverless Functions & Static Assets).

---

## Estructura del Proyecto

```text
/
├── public/                 # Archivos frontend (SPA)
│   ├── index.html          # Dashboard principal y lógica UI
│   ├── frame_ant.html      # Constructor de correos (iFrame)
│   ├── frame_ant.js        # Lógica del constructor de correos
│   └── input.css / output.css # Archivos de Tailwind CSS
├── server.js               # Servidor Express, rutas API y lógica de negocio
├── tailwind.config.js      # Configuración y paleta de colores de Tailwind
├── vercel.json             # Configuración de despliegue para Vercel
├── .agents/                # Reglas y configuraciones para agentes AI
└── README.md               # Este archivo
```

---

## Requisitos Previos e Instalación

1.  **Clonar el repositorio y descargar dependencias**:
    ```bash
    npm install
    ```
2.  **Configurar Variables de Entorno** (`.env`):
    ```env
    PORT=3000
    DATABASE_URL=postgres://user:password@endpoint.neon.tech/dbname
    
    # AWS SES (Para envío de correos)
    AWS_REGION=us-east-1
    AWS_ACCESS_KEY_ID=tu_access_key
    AWS_SECRET_ACCESS_KEY=tu_secret_key
    SES_SENDER_EMAIL=remitente_por_defecto@tudominio.com
    
    # Kinde Auth
    KINDE_CLIENT_ID=tu_client_id
    KINDE_CLIENT_SECRET=tu_client_secret
    KINDE_ISSUER_URL=https://tu_dominio.kinde.com
    KINDE_SITE_URL=http://localhost:3000
    KINDE_POST_LOGOUT_REDIRECT_URL=http://localhost:3000
    
    # Seguridad
    JWT_SECRET=tu_secreto_seguro_para_jwt
    ```
3.  **Inicializar Base de Datos**:
    Al iniciar la aplicación o navegando a `/api/setup-db`, las tablas PostgreSQL se crearán automáticamente.
4.  **Iniciar Servidor**:
    ```bash
    npm run dev
    ```

---

## API & Endpoints Clave

El backend está construido en `server.js` y sirve a la Single Page Application (SPA). A continuación, se detallan los módulos principales de la API (todas las rutas `/api/*` excepto webhooks/tracking están protegidas por `protectRoute` validando el JWT de Kinde):

### Gestión de Autenticación & Usuarios
*   `GET /api/auth/login` | `GET /api/auth/kinde_callback` | `GET /api/auth/logout`: Flujo Kinde OAuth.
*   `GET /api/onboarding` | `POST /api/onboarding`: Gestión del estado de configuración y límites del usuario.

### Base de Contactos y Listas
*   `GET /api/contacts`: Obtiene todos los contactos del usuario.
*   `POST /api/contacts`: Crea/actualiza un contacto individual.
*   `POST /api/contacts/bulk`: Importación masiva con validación deduplicada.
*   `POST /api/contacts/validate-bulk`: Dispara un Job en segundo plano para validar correos vía DNS MX.
*   `GET /api/contacts/custom-fields`: Obtiene claves de campos personalizados (opcionalmente por etiqueta/lista).
*   `GET /api/lists` | `POST /api/lists`: Gestión de nombres de listas/etiquetas.

### Gestión de Formularios
*   `GET /api/forms` | `POST /api/forms` | `DELETE /api/forms/:id`: CRUD de configuraciones de formularios de captación.
*   `GET /form-frame`: Renderiza el formulario estático (iFrame) dinámicamente configurado.
*   `POST /api/contacts/subscribe`: Endpoint público para recibir submissions del formulario.
*   `GET /api/forms/:id/track-view`: Pixel 1x1 público para registrar impresiones de formularios.

### Campañas y Envío
*   `GET /api/campaigns`: Historial de campañas y estado general.
*   `POST /api/send-bulk`: Ejecuta o programa una campaña de envío masivo vía AWS SES (Throttling controlado a 95ms).
*   `GET /api/campaigns/:id/report`: Devuelve analíticas profundas, métricas geográficas y de dispositivos.
*   `GET /api/cron/send-scheduled`: Endpoint (ejecutado por Vercel Cron) que despacha las campañas programadas pendientes.
*   `POST /api/upload-proxy`: Proxy seguro para subir imágenes del constructor de correos a servicios en la nube.

### Tracking y Analíticas (Públicos)
*   `GET /api/campaigns/:id/track-open`: Pixel 1x1 para rastrear aperturas.
*   `GET /api/campaigns/:id/track-click`: Redireccionamiento analítico para medir clics.

### Infraestructura (AWS SES)
*   `GET /api/senders` | `POST /api/senders` | `DELETE /api/senders/:id`: Identidades de envío de AWS SES.
*   `GET /api/domains` | `POST /api/domains`: Generación y validación de registros DKIM.
*   `GET /api/settings/cadence` | `POST /api/settings/cadence`: Configuración de límites de envío por hora y modo Warmup.
*   `POST /api/webhooks/sns`: Listener de notificaciones AWS SNS para registrar Bounces (rebotes) y Complaints (quejas de spam).

---

## Base de Datos (Esquema Principal)

El sistema utiliza PostgreSQL. Las tablas más relevantes (aisladas multitenant por `kinde_id`) incluyen:
*   `users`: Perfil general, configuración de cadencia y volumen mensual.
*   `contacts`: Almacena suscriptores. Soporta campos dinámicos en columna `custom_fields (JSONB)` y matriz `tags`.
*   `campaigns`: Historial y estado de las campañas (incluye conteo de aperturas y clics en bruto).
*   `campaign_opens` / `campaign_clicks`: Logs granulares con Device Type, País, IP y User-Agent.
*   `forms`: Almacena la configuración visual de los formularios (layout, colores, campos), vistas y conversiones.
*   `senders` / `domains`: Registros y estado de verificación de identidades en AWS.

---

## Cron Jobs (Vercel)

Se incluye la configuración de trabajos programados dentro de `vercel.json`:
*   `/api/cron/send-scheduled` configurado para ejecutarse cada 5 minutos (`*/5 * * * *`). Procesa y despacha automáticamente todas las campañas cuyo `scheduled_for` haya sido superado, garantizando el cumplimiento de los límites de velocidad configurados (throttling).

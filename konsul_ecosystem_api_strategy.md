# 🔌 Kônsul Ecosystem — Estrategia de Apificación Estándar

> **Documento técnico para replicar en todas las micro-SaaS del ecosistema Kônsul.**  
> Autor: Kônsul Engineering · Fecha: Julio 2026

---

## 1. Contexto: Por qué apificar correctamente

Cada herramienta del ecosistema Kônsul (Bills, LeadsHUB, CRM, Agentes, etc.) tiene valor por sí sola. Pero el verdadero poder del ecosistema está en la **interoperabilidad**: que una acción en LeadsHUB pueda crear una factura en Bills, que un agente de IA pueda consultar el historial de un cliente, que un dashboard central pueda leer datos de todas las apps.

Para esto, cada micro-SaaS debe exponer una API REST estandarizada, segura, y fácil de consumir. Este documento describe cómo se hizo en **KônsulBills** y cómo replicar ese patrón en cualquier otra app del ecosistema.

---

## 2. Arquitectura de la API en KônsulBills

### 2.1 Stack base
- **Framework:** Next.js 15 (App Router) con Vercel Serverless Functions
- **Base de datos:** Neon PostgreSQL (serverless)
- **Autenticación:** API Keys propias generadas por usuario (sin OAuth en esta fase)
- **Formato:** REST + JSON en todos los endpoints

### 2.2 Estructura de carpetas

```
/api/
  _auth.js              ← Helper central de autenticación
  v1/
    invoices.js         ← CRUD de facturas
    clients.js          ← CRUD de clientes/prospectos
    catalog.js          ← Productos y servicios del catálogo
    summary.js          ← Métricas y resumen financiero
    leadshub.js         ← Webhook dedicado para LeadsHUB
```

> **Regla de oro:** Todo vive bajo `/api/v1/`. La versión en la URL permite hacer breaking changes en el futuro sin romper integraciones existentes. Cuando llegue el momento, se crea `/api/v2/` y ambas conviven.

### 2.3 El Helper de Autenticación (`_auth.js`)

Este es el corazón de la seguridad. **Es el único archivo que toca la lógica de autenticación** y todos los endpoints lo importan. Su funcionamiento:

1. Lee el header `x-api-key` de cada request.
2. Busca en la base de datos si esa API Key existe y está activa.
3. Devuelve el `user_id` asociado a esa key.
4. Si la key no existe o está inactiva, devuelve un error `401 Unauthorized`.

```
[Request entrante]
       ↓
  _auth.js verifica x-api-key
       ↓
  ¿Válida? → SÍ → retorna user_id → el endpoint procede
            → NO → responde 401 y corta la ejecución
```

Los endpoints nunca contienen lógica de autenticación. Solo llaman a `_auth.js` y operan con el `user_id` que reciben. Esto hace que agregar un nuevo endpoint sea trivial y seguro por defecto.

### 2.4 Estructura estándar de un endpoint

Cada endpoint en `/api/v1/` sigue este patrón sin excepción:

```javascript
// 1. CORS headers (para permitir llamadas desde otros dominios)
// 2. Autenticación → obtener userId
// 3. Despachar según método HTTP:
//    GET    → listar o consultar
//    POST   → crear
//    PUT    → actualizar
//    DELETE → eliminar
// 4. Respuesta siempre en formato JSON estándar:

// Éxito:
{ "success": true, "data": { ... } }

// Error:
{ "success": false, "error": "Mensaje descriptivo" }
```

### 2.5 Endpoints disponibles en KônsulBills

| Método | Endpoint | Descripción |
|--------|----------|-------------|
| GET | `/api/v1/invoices` | Lista facturas del usuario autenticado |
| POST | `/api/v1/invoices` | Crea una nueva factura |
| GET | `/api/v1/invoices?id=xxx` | Obtiene detalle de una factura |
| PUT | `/api/v1/invoices` | Actualiza una factura existente |
| GET | `/api/v1/clients` | Lista clientes/prospectos |
| POST | `/api/v1/clients` | Crea un cliente o prospecto |
| GET | `/api/v1/catalog` | Lista productos/servicios del catálogo |
| POST | `/api/v1/catalog` | Agrega un item al catálogo |
| GET | `/api/v1/summary` | Métricas: total facturado, pendiente, pagado |
| POST | `/api/v1/leadshub` | Webhook de LeadsHUB para sincronizar leads |

### 2.6 Autenticación: cómo usar la API

Todo request debe incluir dos headers:

```
x-api-key: kb_live_xxxxxxxxxxxxxxxxxxxx
x-user-id: uuid-del-usuario
```

La API Key se genera desde la sección **Ajustes → API & Integraciones** dentro de la app.

---

## 3. Cómo replicar este patrón en otra micro-SaaS

Para apificar cualquier otra herramienta del ecosistema Kônsul (ej: LeadsHUB, Agentes, CRM), seguir estos pasos exactos:

### Paso 1: Crear la tabla de API Keys en la base de datos

```sql
CREATE TABLE api_keys (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id),
  key_value TEXT NOT NULL UNIQUE,
  name TEXT,                          -- "Mi integración con LeadsHUB"
  is_active BOOLEAN DEFAULT true,
  scopes TEXT[],                      -- ["read:invoices", "write:invoices"]
  last_used_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ DEFAULT NOW()
);
```

> **Nota sobre Scopes:** Aunque en la fase actual KônsulBills usa acceso completo por key, se recomienda agregar `scopes` desde el inicio. Los scopes permiten crear keys de solo lectura, keys para una sola app, etc.

### Paso 2: Copiar `_auth.js` y adaptarlo

El helper `_auth.js` es prácticamente idéntico en todas las apps. Solo cambia el nombre de la tabla de api_keys y el campo de conexión a la base de datos. El archivo se copia tal cual y se ajusta en 2-3 líneas.

### Paso 3: Crear la carpeta `/api/v1/`

Cada recurso principal de la app tiene su propio archivo. Por ejemplo, en una app de agentes de IA sería:

```
/api/v1/agents.js
/api/v1/conversations.js  
/api/v1/knowledge.js
/api/v1/channels.js
```

### Paso 4: Implementar CORS y el formato de respuesta estándar

Copiar los headers CORS del patrón Bills. El formato de respuesta `{ success, data, error }` debe ser idéntico en todas las apps del ecosistema para que los clientes puedan manejar errores de forma uniforme.

### Paso 5: Crear la UI de gestión de API Keys en Ajustes

Cada app debe tener en su sección de ajustes:
- Botón para generar nueva API Key
- Listado de keys activas
- Botón para revocar/deshabilitar una key
- Documentación embebida con ejemplos de uso

---

## 4. La visión: Ecosistema Plug & Play

### 4.1 El problema actual

Hoy en día, conectar dos apps del ecosistema Kônsul requiere:
1. Ir a App A → Ajustes → API → Generar key → Copiar
2. Ir a App B → Ajustes → Integraciones → Pegar key → Guardar
3. Repetir por cada app que se quiera conectar

Esto es tedioso, propenso a errores y no escala cuando el ecosistema tiene 5, 10 o 15 micro-SaaS.

### 4.2 La solución: Kônsul Connect (Identity Bridge)

El modelo a implementar es un **hub central de autenticación e identidad** que actúa como intermediario entre todas las apps. El usuario solo necesita conectar una vez.

```
┌─────────────────────────────────────────────────┐
│              KÔNSUL CONNECT (Hub Central)        │
│                                                  │
│  • Un solo login / una sola identidad            │
│  • Gestión central de permisos por app           │
│  • Token maestro que se traduce por app          │
└────────────┬─────────────────┬───────────────────┘
             │                 │
    ┌────────▼───┐      ┌──────▼──────┐
    │ KônsulBills│      │  LeadsHUB   │    ... otras apps
    │  /api/v1/  │      │  /api/v1/   │
    └────────────┘      └─────────────┘
```

**Flujo del usuario con Kônsul Connect:**

1. El usuario entra a LeadsHUB.
2. Va a **Integraciones → KônsulBills**.
3. Hace clic en **"Conectar"**.
4. Aparece un popup (similar a OAuth) mostrando qué permisos necesita LeadsHUB en Bills.
5. El usuario aprueba con un clic.
6. La conexión queda activa. LeadsHUB puede ahora crear facturas en Bills sin que el usuario toque ninguna API key.

### 4.3 Implementación técnica del Plug & Play

#### Fase 1 (corto plazo): Service-to-Service con keys de servicio

Antes de tener el hub completo, se puede hacer una versión simplificada:

- Cada app genera una **Service Key** especial (además de las user keys).
- Las Service Keys tienen un prefijo diferente: `kb_svc_xxx` para Bills, `lh_svc_xxx` para LeadsHUB.
- En los ajustes de LeadsHUB, hay un campo **"Conectar con KônsulBills"** donde el usuario pega su `kb_svc_xxx` **una sola vez**.
- LeadsHUB almacena esa key de forma segura y la usa en cada llamada automáticamente.

Esto ya elimina 80% de la fricción sin necesidad de un hub central.

#### Fase 2 (medio plazo): Kônsul Connect OAuth-style

Implementar un servidor de autorización propio (puede ser simple, basado en Neon):

```
1. App B redirige al usuario a: konsul.digital/connect?app=bills&scopes=read:invoices,write:invoices&redirect_uri=...
2. El usuario ve la pantalla de consentimiento: "LeadsHUB quiere acceder a tus Facturas en Bills. ¿Autorizar?"
3. El usuario hace clic en "Autorizar".
4. Kônsul Connect genera un token de acceso temporal y redirige de vuelta a App B.
5. App B intercambia el token temporal por un token permanente de larga duración.
6. Listo. La conexión está activa sin que el usuario haya tocado ninguna API key.
```

Este flujo es idéntico al OAuth 2.0 que usa Google, GitHub o Stripe. La ventaja es que ya existe documentación extensa y librerías para esto.

#### Fase 3 (largo plazo): Kônsul App Store

Un marketplace interno donde el usuario ve todas las apps del ecosistema, cuáles tiene activas, qué permisos tiene cada integración, y puede activar/desactivar conexiones con un toggle. Similar al panel de "Apps conectadas" de Slack o Notion.

---

## 5. Estándares que deben seguir TODAS las apps del ecosistema

Para que el ecosistema funcione de forma cohesiva, cada app debe adherirse a estos estándares:

### 5.1 Nomenclatura de API Keys

| App | Prefijo de key |
|-----|---------------|
| KônsulBills | `kb_live_` |
| LeadsHUB | `lh_live_` |
| Agentes IA | `ag_live_` |
| CRM Kônsul | `crm_live_` |

Para keys de servicio (app-to-app): reemplazar `live` por `svc`.
Para keys de test: reemplazar `live` por `test`.

### 5.2 Formato de respuesta HTTP

Todas las apps deben responder con exactamente este formato:

```json
// Éxito
{
  "success": true,
  "data": { ... },
  "meta": {
    "page": 1,
    "total": 42,
    "app": "konsulbills",
    "version": "1"
  }
}

// Error
{
  "success": false,
  "error": {
    "code": "UNAUTHORIZED",
    "message": "API key inválida o expirada"
  }
}
```

### 5.3 Códigos de error estándar

| Código | HTTP Status | Significado |
|--------|-------------|-------------|
| `UNAUTHORIZED` | 401 | API key inválida o faltante |
| `FORBIDDEN` | 403 | Key válida pero sin permiso para esta acción |
| `NOT_FOUND` | 404 | El recurso solicitado no existe |
| `VALIDATION_ERROR` | 422 | Los datos enviados tienen errores |
| `RATE_LIMITED` | 429 | Demasiadas requests (implementar a futuro) |
| `SERVER_ERROR` | 500 | Error interno del servidor |

### 5.4 Versioning

- Siempre empezar en `/api/v1/`.
- Nunca hacer breaking changes en una versión existente.
- Al introducir cambios incompatibles, crear `/api/v2/` y mantener `/api/v1/` activo por al menos 6 meses.
- Anunciar deprecaciones con al menos 3 meses de anticipación.

### 5.5 Headers requeridos en toda respuesta

```
Content-Type: application/json
X-App-Version: 1.0.0
X-Request-Id: uuid-unico-por-request  ← para debugging
Access-Control-Allow-Origin: *         ← o dominio específico
```

### 5.6 Rate Limiting (implementar desde el inicio)

Aunque en la fase actual no se aplica rate limiting, la arquitectura debe prepararse para ello:
- Máximo 1,000 requests por hora por API key (tier básico)
- Máximo 10,000 requests por hora (tier profesional)
- Headers de respuesta: `X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Reset`

---

## 6. Checklist para apificar una nueva micro-SaaS

Usar esta lista al implementar la API en cualquier nueva app del ecosistema:

- [ ] Crear tabla `api_keys` en la base de datos con campos: id, user_id, key_value, name, is_active, scopes, last_used_at
- [ ] Copiar y adaptar `_auth.js` de KônsulBills
- [ ] Crear carpeta `/api/v1/`
- [ ] Implementar CORS en todos los endpoints
- [ ] Usar formato de respuesta estándar `{ success, data/error }`
- [ ] Usar prefijo de key correcto según la app (`kb_`, `lh_`, `ag_`, etc.)
- [ ] Crear UI en Ajustes para generar/revocar API Keys
- [ ] Generar documentación `.md` con ejemplos en cURL, Python y JS
- [ ] Agregar botón de descarga de la documentación en Ajustes
- [ ] Publicar el archivo `.md` en la carpeta `public/` del proyecto
- [ ] Crear endpoint de health check: `GET /api/v1/health` → `{ "status": "ok", "app": "nombre-app" }`
- [ ] Hacer commit y push con tag de versión

---

## 7. Resumen ejecutivo

KônsulBills estableció el **patrón base** que todas las apps del ecosistema deben seguir:

1. **Autenticación centralizada** en un helper único (`_auth.js`) que verifica API Keys almacenadas en la base de datos.
2. **Endpoints versionados** bajo `/api/v1/` con un archivo por recurso.
3. **Formato de respuesta uniforme** para que cualquier cliente pueda consumir cualquier app sin aprender una nueva API.
4. **UI de gestión** integrada en los Ajustes de cada app para que el usuario pueda gestionar sus keys sin salir de la herramienta.
5. **Documentación descargable** generada automáticamente para facilitar la integración por parte de desarrolladores externos.

La visión a futuro es **Kônsul Connect**: un hub central de autenticación OAuth-style que permita conectar cualquier app del ecosistema con un solo clic, sin copiar y pegar API keys, gestionando permisos de forma granular y ofreciendo un App Store interno para que el usuario vea y controle todas sus integraciones desde un solo lugar.

---

*Este documento es propiedad de Kônsul · Uso interno del equipo de ingeniería.*

# NEXUS FIREWALL v1.0 — Android + Servidor Hostinger

## Qué incluye
| Parte | Dónde |
|---|---|
| App Android (Kotlin, sin root) | `app/` |
| Servidor de un solo archivo (licencias, PayPal, MCP remoto, IA) | `server/nexus_firewall_server.php` |
| Compilación automática del APK en GitHub | `.github/workflows/build-apk.yml` |

### Funciones de la app
- **Bloqueador de anuncios** por DNS (VPN local, todo se queda en tu teléfono) con listas StevenBlack, AdAway, OISD y Peter Lowe, y puedes agregar más.
- **Aprendizaje**: detecta dominios nuevos de anuncios o rastreo por patrones y los bloquea solo. Con **🤖 Analizar con IA**, Gemini revisa los dominios que vio tu teléfono.
- **Firewall por app**: 🌐 quita el internet a la app que elijas.
- **Tú decides quién pasa**: con 🛡 en NO, la app pasa sin bloqueador.
- **Registro en vivo**: tocas un dominio y eliges bloquear, permitir, bloquear el dominio raíz o quitarle el internet a la app.
- **MCP local**: tus IA (una o varias, cada una con su token de *lectura* o *control total*) controlan el firewall desde el mismo teléfono o desde tu PC en la misma Wi-Fi.
- **MCP remoto (URL)**: `https://tudominio.com/nexus_firewall_server.php?mcp=1`. Tus IA controlan el teléfono desde cualquier lugar. Un token **admin** también administra el proyecto: usuarios, premium, planes, pagos y qué funciones son premium.
- **Asistente IA** dentro de la app: le das órdenes en español y te pide confirmación antes de ejecutar.
- **Mis VPN**: ves tus VPN instaladas y cambias a una con un toque. También puedes usar el DNS de tu VPN como DNS superior.
- **Clonador de apps**: crea un espacio clonado (perfil de trabajo) y ahí clonas WhatsApp, Instagram, etc.
- **Temas**: Rojo/Negro (por defecto), Rojo Neón y temas premium (Sangre, Cyber Azul, Matrix, Morado, Oro).
- **Gratis / Premium**: tú eliges desde el panel qué funciones son premium, das días o premium ilimitado, fijas precios y los pagos llegan por PayPal a **larchss21@gmail.com**.

---

## 1) Subir el servidor a Hostinger
1. En hPanel › **Bases de datos MySQL**, crea una base y anota el nombre, el usuario y la contraseña.
2. En el **Administrador de archivos**, sube `nexus_firewall_server.php` a `public_html/`.
3. Abre `https://tudominio.com/nexus_firewall_server.php`, llena los datos y pon tu contraseña de admin. Se crea solo el archivo `nexus_fw_config.php`.
4. En el panel › **Ajustes**:
   - **PayPal**: entra a developer.paypal.com con larchss21@gmail.com › *Apps & Credentials* › **Live** › *Create App* › copia el **Client ID** y el **Secret**. Para hacer pruebas, primero usa el modo *sandbox*.
   - **Gemini**: pega tu clave y toca **Cargar modelos de mi cuenta** para elegir el modelo. No hay ningún modelo escrito en el código.
   - Marca qué funciones son **Premium**.
5. En **Planes**, crea tus planes, por ejemplo: Mensual, 30 días, 2.99 USD; Anual, 365 días; Para siempre, 0 días.
6. En **Usuarios** das o quitas días, premium ilimitado, fechas, suspensiones y cambias contraseñas.

## 2) Sacar el APK (GitHub lo compila gratis)
1. Crea un repositorio **privado** en github.com (por ejemplo `nexus-firewall`).
2. Sube **todo el contenido** de esta carpeta, incluidas `.github/`, `gradle/`, `keystore.properties` y `app/nexus-release.jks`. Desde la PC: *Add file › Upload files* y arrastra las carpetas.
3. Ve a la pestaña **Actions** › **Compilar APK Nexus Firewall**. Tarda unos 5 minutos y luego descargas **NexusFirewall-APK**.
4. Instálalo en tu S25 Ultra (permite "instalar apps desconocidas").

> La llave `nexus-release.jks` es fija: cada APK nuevo se instala **encima** del anterior y conservas tus reglas. Guárdala y no la compartas. Por eso conviene que el repositorio sea privado.

Otra opción: abre la carpeta en **Android Studio** › *Build › Build APK*.

## 3) Configurar la app
1. Pestaña **Cuenta**: pega la URL de tu servidor y regístrate o entra. Sin servidor, la app funciona con **todo desbloqueado** (modo dueño).
2. En **Panel** toca **ACTIVAR** y acepta el permiso VPN.
3. **Importante**: en Android, ve a *Ajustes › Conexiones › Más ajustes de conexión › DNS privado* y ponlo en **Desactivado**. En Chrome, desactiva *DNS seguro*. Si no, las apps se saltan el filtro.
4. Para que no se apague: *Ajustes › VPN* › Nexus › **VPN siempre activa**, y quita la optimización de batería.

## 4) Conectar tus IA por MCP
**Desde el teléfono o tu Wi-Fi:** en la pestaña IA/MCP activa el *MCP local*, crea un token y toca **Copiar config**:
```json
{ "mcpServers": { "nexus-firewall": { "type": "http",
  "url": "http://192.168.1.50:8765/mcp",
  "headers": { "Authorization": "Bearer TU_TOKEN" } } } }
```
**Desde cualquier lugar (URL):** en el panel › **MCP / IA**, crea un token (lectura, total o admin) y copia la config que aparece. En la app activa **Control remoto**. Las órdenes llegan al teléfono en unos 8 segundos.

Herramientas: `get_status`, `start_firewall`, `stop_firewall`, `get_logs`, `top_domains`, `list_apps`, `set_app_rule`, `block_domain`, `allow_domain`, `remove_domain_rule`, `list_rules`, `set_learning`, `set_upstream_dns`, `update_blocklists`, `add_blocklist`, `clear_logs`. Con un token admin se agregan `list_users`, `grant_premium`, `revoke_premium`, `list_payments`, `list_plans`, `set_plan` y `set_premium_features`.

## Límites reales de Android (para que no te sorprendan)
- **Una sola VPN a la vez**: Android no permite tener Nexus y otra VPN activas al mismo tiempo. Por eso está *Mis VPN* (cambio rápido) y la opción de usar el DNS de tu VPN en Nexus.
- **Anuncios de YouTube, Instagram y Facebook** salen del mismo servidor que el contenido. Ningún bloqueador por DNS los quita sin romper la app.
- El **firewall por app** funciona con las apps que usan el DNS del sistema (casi todas). Una app con DNS cifrado propio puede saltárselo.
- **Clonador**: Android permite **un** espacio clonado, o sea, una copia extra por app. Si ya tienes un perfil de trabajo (por ejemplo el de una empresa), quítalo primero. La Carpeta Segura de Samsung es aparte y sigue funcionando.

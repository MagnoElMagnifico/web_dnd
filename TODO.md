Minimos:

- [ ] Sistema DM/Jugador
- [ ] Mapa (PNG)
- [ ] Personajes (q se vean)
- [ ] Movimiento
- [ ] Enemigos controlados DM
- [ ] Manejar HP

Objetivos:

- [ ] DM controla turnos
- [ ] GUI
- [ ] Mapa interactivo
- [x] Cookies
- [ ] Medidas de distancia
- [ ] Ataques a escala
- [ ] Datos de personaje
- [ ] Creador de ataques
- [ ] Creador de mapas
- [ ] Creador de enemigos
- [ ] Diferentes tipos de enemigos
- [ ] Dados
- [ ] Log de combate

Extras:

- [ ] Lista de hechizos
- [ ] Inventario?
- [ ] Enemigos (AI)
- [ ] Editor de mapa en tiempo real
- [ ] Unity Particle System
- [ ] Animaciones
- [ ] Graficos
- [ ] Sonido
- [ ] Custom players

# Server

- [ ] Caché
- [ ] Cookies
- [ ] Más métodos: `POST`, `PUT`, `HEAD`, `OPTIONS`...
- [ ] Manejar WebSockets


# Structure

backend:

- `__main__`: setup the config
- `database`: transaction implementation
- `http_msp`: abstraction over http
- `security`: password hasher and ID generation
- `server`: server logic implementation

frontend - public paths (some of these paths are hardcoded in the server):
 
- `styles`: CSS, fonts, images used for the style (favicon, logos, etc)
- `base.html`: template file which serves as a base for all the remaining HTML
- `error.html`: template file for server errors
- `index.html`: login page
- `login-signup.js`: login and signup logic

frontend - private paths (only accessible with a valid SID):

- `index.html`: user dashboard (campaigns)

# Templates

- `{{ template:base|<file>.html }}`: specifies which template to use. If it is
  `base`, the file is itself a template.
- `{{ define "<name>" }}`: defines an extension point. Only useful when
  `template:base`.
- `{{ block "<name>" }}...{{ /block }}`: specifies what to put on the
  definition.
- `{{ code }}`, `{{ phrase }}`, `{{ description }}`: information about the
  error. Only useful in `error.html`

## Example

`base.html`:

```
{{ template:base }}

=================================================
    {{ define "title" }}
=================================================
```

`index.html`:

```
{{ template:base.html }}

{{ block "title" }}Hello world!{{ /block }}
```

The previous file will be converted into:

```
{{ template:base }}

=================================================
    Hello world!
=================================================
```

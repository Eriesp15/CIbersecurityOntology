# Motor de Búsqueda para Ontología de Ciberseguridad

Sistema de búsqueda multilingüe (español/inglés) para ontologías OWL.

## 📋 Características

- ✅ Búsqueda en clases, propiedades e individuos
- ✅ Soporte multilingüe (ES/EN)
- ✅ Filtros por tipo de entidad
- ✅ Vista detallada con navegación entre conceptos
- ✅ Interfaz moderna y responsive
- ✅ Ranking de resultados por relevancia
- ✅ Estadísticas de la ontología

## 🚀 Instalación

### 1. Estructura del proyecto

Crea la siguiente estructura de carpetas:

```
ontology-search/
│
├── app.py                          # Backend Flask
├── requirements.txt                # Dependencias
├── CibersecurityOntology.rdf       # Tu ontología OWL
│
└── templates/
    └── index.html                  # Frontend
```

### 2. Instalar dependencias

# Instalar dependencias
pip install -r requirements.txt



### 3. Ejecución
# Ejecutar el comando

```bash
python app.py
```

El servidor se iniciará en: **http://127.0.0.1:5000/**

## 🎯 Uso

1. **Buscar**: Escribe un término en la barra de búsqueda
2. **Filtrar**: Selecciona "Clases", "Propiedades" o "Individuos"
3. **Cambiar idioma**: Haz clic en ES 🇪🇸 o EN 🇺🇸
4. **Ver detalles**: Haz clic en cualquier resultado
5. **Navegar**: En la vista detallada, haz clic en conceptos relacionados

## 🔧 Personalización

### Cambiar colores

Edita en `templates/index.html` las siguientes líneas:

```css
/* Línea 14 - Fondo degradado */
background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);

/* Línea 184 - Botones */
background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
```

### Modificar límite de resultados

En `app.py`, línea 237:

```python
'results': results[:50]  # Cambia 50 por el número que desees
```

### Agregar más idiomas

1. En `app.py`, modifica las funciones `get_label()` y `get_comment()` para aceptar más idiomas
2. En `templates/index.html`, agrega traducciones al objeto `translations`
3. Agrega botones de idioma en el HTML

## 📊 API Endpoints

### GET /api/search
Busca en la ontología

**Parámetros:**
- `q`: término de búsqueda (requerido)
- `lang`: idioma (es/en, default: es)
- `type`: filtro (all/class/property/individual, default: all)

**Ejemplo:**
```
GET /api/search?q=malware&lang=es&type=class
```

### GET /api/details/<entity_name>
Obtiene detalles de una entidad

**Parámetros:**
- `lang`: idioma (es/en, default: es)

**Ejemplo:**
```
GET /api/details/Malware?lang=en
```

### GET /api/stats
Obtiene estadísticas de la ontología

**Ejemplo:**
```
GET /api/stats
```

## 🐛 Solución de Problemas

### Error: "Ontología no cargada"
- Verifica que el archivo OWL existe en la ruta especificada
- Revisa que el archivo OWL no esté corrupto

### Error: "ModuleNotFoundError: No module named 'owlready2'"
- Ejecuta: `pip install owlready2`

### No aparecen las etiquetas en español/inglés
- Verifica que tu ontología tiene anotaciones `rdfs:label` con tags de idioma
- Revisa en Protégé que las anotaciones estén correctamente configuradas

### Los resultados no son relevantes
- Ajusta la función `calculate_relevance()` en `app.py` (línea 137)
- Modifica los pesos de coincidencia según tus necesidades

## 🎨 Capturas de Pantalla

El sistema incluye:
- 📊 Dashboard con estadísticas
- 🔍 Búsqueda con autocompletado visual
- 🏷️ Filtros por tipo de entidad
- 📱 Diseño responsive
- 🌐 Cambio de idioma en tiempo real
- 📄 Vista detallada modal con navegación

## 📝 Mejoras Futuras

- [ ] Autocompletado de búsqueda
- [ ] Exportar resultados a PDF/CSV
- [ ] Visualización de grafo de relaciones
- [ ] Búsqueda avanzada con operadores lógicos
- [ ] Historial de búsquedas
- [ ] Favoritos/marcadores
- [ ] API REST documentada con Swagger

## 👨‍💻 Tecnologías

- **Backend**: Python 3.8+, Flask
- **Ontología**: Owlready2, RDF/OWL
- **Frontend**: HTML5, CSS3, JavaScript (Vanilla)
- **Diseño**: CSS Grid, Flexbox

## 📄 Licencia

Este proyecto es de código abierto para uso educativo.

## 🤝 Contribuciones

Si encuentras bugs o tienes sugerencias, ¡son bienvenidas!

---

Desarrollado para proyecto académico de Ontologías de Ciberseguridad
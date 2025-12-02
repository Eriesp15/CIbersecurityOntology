from flask import Flask, render_template, request, jsonify
from flask_cors import CORS
from owlready2 import get_ontology, locstr
import unicodedata
import os
from SPARQLWrapper import SPARQLWrapper, JSON
import re

app = Flask(__name__, template_folder='templates')
CORS(app)

# Cargar la ontología
ontology = None
ONTOLOGY_PATH = "CibersecurityOntology.rdf"

# Endpoints de DBpedia por idioma
DBPEDIA_ENDPOINTS = {
    'en': "https://dbpedia.org/sparql",
    'es': "https://es.dbpedia.org/sparql", 
    'fr': "https://fr.dbpedia.org/sparql",
    'de': "https://de.dbpedia.org/sparql",
    'it': "https://it.dbpedia.org/sparql",
    'pt': "https://pt.dbpedia.org/sparql"
}

def load_ontology():
    global ontology
    if os.path.exists(ONTOLOGY_PATH):
        abs_path = os.path.abspath(ONTOLOGY_PATH)
        ontology = get_ontology(abs_path).load()
        print(f"✅ Ontología cargada: {len(list(ontology.classes()))} clases, {len(list(ontology.individuals()))} individuos")
    else:
        print(f"❌ Error: No se encuentra {ONTOLOGY_PATH}")

def get_label(entity, lang='es'):
    """Obtiene la etiqueta en el idioma especificado"""
    if hasattr(entity, 'label'):
        labels = entity.label
        if labels:
            # Buscar en el idioma especificado
            for label in labels:
                if hasattr(label, 'lang') and label.lang == lang:
                    return str(label)
            
            # Si no encuentra en el idioma especificado, buscar en inglés
            if lang != 'en':
                for label in labels:
                    if hasattr(label, 'lang') and label.lang == 'en':
                        return str(label)
            
            # Si no encuentra ni en el idioma especificado ni en inglés, devolver el primero
            return str(labels[0]) if labels else entity.name
    return entity.name

def get_comment(entity, lang='es'):
    """Obtiene el comentario en el idioma especificado"""
    if hasattr(entity, 'comment'):
        comments = entity.comment
        if comments:
            # Buscar en el idioma especificado
            for comment in comments:
                if hasattr(comment, 'lang') and comment.lang == lang:
                    return str(comment)
            
            # Si no encuentra en el idioma especificado, buscar en inglés
            if lang != 'en':
                for comment in comments:
                    if hasattr(comment, 'lang') and comment.lang == 'en':
                        return str(comment)
            
            # Si no encuentra ni en el idioma especificado ni en inglés, devolver el primero
            return str(comments[0]) if comments else ""
    return ""

def normalize_text(text):
    if text is None:
        return ""
    t = unicodedata.normalize('NFKD', str(text))
    t = t.encode('ascii', 'ignore').decode('ascii')
    return t.strip().lower()

def search_classes(query, lang='es'):
    """Busca en las clases de la ontología"""
    results = []
    query_lower = normalize_text(query)
    
    for cls in ontology.classes():
        label_display = get_label(cls, lang)
        label = normalize_text(label_display)
        comment = normalize_text(get_comment(cls, lang))
        name = normalize_text(cls.name)
        
        if query_lower in label or query_lower in name or query_lower in comment:
            parents = [{'name': p.name, 'label': get_label(p, lang)} for p in cls.is_a if isinstance(p, type)]
            subclasses = [{'name': sub.name, 'label': get_label(sub, lang)} for sub in cls.subclasses()]
            
            results.append({
                'name': cls.name,
                'label': label_display,
                'type': 'Clase',
                'comment': get_comment(cls, lang) or f"Clase de ciberseguridad ({lang})",
                'parents': [p['label'] for p in parents[:3]],
                'subclasses': [s['label'] for s in subclasses[:5]],
                'relevance': calculate_relevance(query_lower, label, name, comment, 'class'),
                'source': 'offline'
            })
    
    return results

def search_properties(query, lang='es'):
    """Busca en las propiedades de la ontología"""
    results = []
    query_lower = normalize_text(query)
    
    for prop in ontology.object_properties():
        label_display = get_label(prop, lang)
        label = normalize_text(label_display)
        comment = normalize_text(get_comment(prop, lang))
        name = normalize_text(prop.name)
        
        if query_lower in label or query_lower in name or query_lower in comment:
            domain = [{'name': d.name, 'label': get_label(d, lang)} for d in prop.domain] if prop.domain else []
            range_val = [{'name': r.name, 'label': get_label(r, lang)} for r in prop.range] if prop.range else []
            
            results.append({
                'name': prop.name,
                'label': label_display,
                'type': 'Propiedad',
                'comment': get_comment(prop, lang) or f"Propiedad de la ontología ({lang})",
                'domain': [d['label'] for d in domain],
                'range': [r['label'] for r in range_val],
                'relevance': calculate_relevance(query_lower, label, name, comment, 'property'),
                'source': 'offline'
            })
    
    for prop in ontology.data_properties():
        label_display = get_label(prop, lang)
        label = normalize_text(label_display)
        comment = normalize_text(get_comment(prop, lang))
        name = normalize_text(prop.name)
        
        if query_lower in label or query_lower in name or query_lower in comment:
            domain = [{'name': d.name, 'label': get_label(d, lang)} for d in prop.domain] if prop.domain else []
            
            results.append({
                'name': prop.name,
                'label': label_display,
                'type': 'Propiedad',
                'comment': get_comment(prop, lang) or f"Propiedad de datos ({lang})",
                'domain': [d['label'] for d in domain],
                'range': [],
                'relevance': calculate_relevance(query_lower, label, name, comment, 'property'),
                'source': 'offline'
            })
    
    return results

def search_individuals(query, lang='es'):
    """Busca en los individuos de la ontología"""
    results = []
    query_lower = normalize_text(query)
    
    for ind in ontology.individuals():
        label_display = get_label(ind, lang)
        label = normalize_text(label_display)
        name = normalize_text(ind.name)
        comment = normalize_text(get_comment(ind, lang))
        
        if query_lower in label or query_lower in name or query_lower in comment:
            classes = [{'name': c.name, 'label': get_label(c, lang)} for c in ind.is_a if isinstance(c, type)]
            
            results.append({
                'name': ind.name,
                'label': label_display,
                'type': 'Individuo',
                'comment': get_comment(ind, lang) or f"Instancia de ciberseguridad ({lang})",
                'classes': [c['label'] for c in classes],
                'relevance': calculate_relevance(query_lower, label, name, comment, 'individual'),
                'source': 'offline'
            })
    
    return results

def calculate_relevance(query, label, name, comment, entity_type):
    """Calcula la relevancia de un resultado"""
    score = 0
    if query == label:
        score += 120
    elif label.startswith(query):
        score += 70
    elif query in label:
        score += 40
    if query == name:
        score += 90
    elif name.startswith(query):
        score += 60
    elif query in name:
        score += 30
    if query and comment and query in comment:
        score += 20
    score -= len(label) * 0.1
    if entity_type == 'class':
        score += 5
    elif entity_type == 'individual':
        score += 3
    return score

def search_dbpedia_online(query, lang='es', limit=10):
    """Busca en DBpedia en línea en el idioma especificado"""
    # Si la consulta está vacía o es muy corta, retornar vacío
    if not query or len(query.strip()) < 2:
        return []
    
    query = query.strip()
    
    try:
        # Seleccionar endpoint según idioma
        endpoint = DBPEDIA_ENDPOINTS.get(lang, DBPEDIA_ENDPOINTS['en'])
        
        # Código de idioma para SPARQL
        lang_codes = {
            'en': 'en',
            'es': 'es',
            'fr': 'fr', 
            'de': 'de',
            'it': 'it',
            'pt': 'pt'
        }
        lang_code = lang_codes.get(lang, 'en')
        
        # Crear conexión SPARQL
        sparql = SPARQLWrapper(endpoint)
        sparql.addCustomHttpHeader("User-Agent", "CybersecuritySearchBot/1.0")
        sparql.setTimeout(20)  # 20 segundos de timeout
        
        print(f"🔍 Buscando en DBpedia ({lang}): '{query}'")
        
        # PARA INGLÉS: Búsqueda con filtros de ciberseguridad
        if lang == 'en':
            # Términos de ciberseguridad en inglés
            security_terms = [
                'security', 'cyber', 'malware', 'ransomware', 'hacker',
                'virus', 'attack', 'firewall', 'antivirus', 'phishing',
                'botnet', 'vulnerability', 'encryption', 'cryptography',
                'spyware', 'trojan', 'worm', 'exploit', 'breach',
                'intrusion', 'detection', 'network', 'information',
                'computer', 'data', 'protection', 'defense'
            ]
            
            # Construir filtro de categorías
            category_filters = []
            for term in security_terms:
                category_filters.append(f'CONTAINS(LCASE(STR(?category)), "{term}")')
            
            category_filter = " || ".join(category_filters)
            
            # Consulta SPARQL para inglés
            search_query = f"""
            PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
            PREFIX dbo: <http://dbpedia.org/ontology/>
            PREFIX dct: <http://purl.org/dc/terms/>

            SELECT DISTINCT ?resource ?label ?abstract WHERE {{
              {{
                ?resource rdfs:label ?label .
                FILTER(CONTAINS(LCASE(?label), "{query.lower()}") && LANG(?label) = 'en')
                OPTIONAL {{ ?resource dbo:abstract ?abstract . FILTER(LANG(?abstract) = 'en') }}
                OPTIONAL {{ ?resource dct:subject ?category . }}
                FILTER({category_filter} || !BOUND(?category))
              }}
              UNION
              {{
                ?resource dbo:abstract ?abstract .
                FILTER(CONTAINS(LCASE(?abstract), "{query.lower()}") && LANG(?abstract) = 'en')
                ?resource rdfs:label ?label . FILTER(LANG(?label) = 'en')
                OPTIONAL {{ ?resource dct:subject ?category . }}
                FILTER({category_filter} || !BOUND(?category))
              }}
            }}
            ORDER BY ?label
            LIMIT {limit}
            """
        
        # PARA ESPAÑOL: Búsqueda con filtros de ciberseguridad
        elif lang == 'es':
            # Términos de ciberseguridad en español
            security_terms = [
                'seguridad', 'ciber', 'malware', 'ransomware', 'hacker',
                'virus', 'ataque', 'cortafuegos', 'antivirus', 'phishing',
                'botnet', 'vulnerabilidad', 'cifrado', 'criptografía',
                'spyware', 'troyano', 'gusano', 'explotación', 'brecha',
                'intrusión', 'detección', 'red', 'información',
                'ordenador', 'datos', 'protección', 'defensa'
            ]
            
            # Construir filtro de categorías
            category_filters = []
            for term in security_terms:
                category_filters.append(f'CONTAINS(LCASE(STR(?category)), "{term}")')
            
            category_filter = " || ".join(category_filters)
            
            # Consulta SPARQL para español
            search_query = f"""
            PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
            PREFIX dbo: <http://dbpedia.org/ontology/>
            PREFIX dct: <http://purl.org/dc/terms/>

            SELECT DISTINCT ?resource ?label ?abstract WHERE {{
              {{
                ?resource rdfs:label ?label .
                FILTER(CONTAINS(LCASE(?label), "{query.lower()}") && LANG(?label) = 'es')
                OPTIONAL {{ ?resource dbo:abstract ?abstract . FILTER(LANG(?abstract) = 'es') }}
                OPTIONAL {{ ?resource dct:subject ?category . }}
                FILTER({category_filter} || !BOUND(?category))
              }}
              UNION
              {{
                ?resource dbo:abstract ?abstract .
                FILTER(CONTAINS(LCASE(?abstract), "{query.lower()}") && LANG(?abstract) = 'es')
                ?resource rdfs:label ?label . FILTER(LANG(?label) = 'es')
                OPTIONAL {{ ?resource dct:subject ?category . }}
                FILTER({category_filter} || !BOUND(?category))
              }}
            }}
            ORDER BY ?label
            LIMIT {limit}
            """
        
        # PARA OTROS IDIOMAS (francés, alemán, italiano, portugués): Búsqueda simple
        else:
            # Consulta SPARQL simple para otros idiomas
            search_query = f"""
            PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
            PREFIX dbo: <http://dbpedia.org/ontology/>

            SELECT DISTINCT ?resource ?label ?abstract WHERE {{
              ?resource rdfs:label ?label .
              FILTER(CONTAINS(LCASE(?label), "{query.lower()}") && LANG(?label) = '{lang_code}')
              OPTIONAL {{ ?resource dbo:abstract ?abstract . FILTER(LANG(?abstract) = '{lang_code}') }}
            }}
            ORDER BY ?label
            LIMIT {limit}
            """
        
        # Ejecutar la consulta
        sparql.setQuery(search_query)
        sparql.setReturnFormat(JSON)
        
        results = sparql.query().convert()
        
        formatted_results = []
        for result in results["results"]["bindings"]:
            try:
                resource_uri = result["resource"]["value"]
                resource_name = resource_uri.split("/")[-1]
                
                # Determinar enlace según idioma
                if lang == 'es':
                    external_link = f"https://es.dbpedia.org/page/{resource_name}"
                elif lang == 'fr':
                    external_link = f"https://fr.dbpedia.org/page/{resource_name}"
                elif lang == 'de':
                    external_link = f"https://de.dbpedia.org/page/{resource_name}"
                elif lang == 'it':
                    external_link = f"https://it.dbpedia.org/page/{resource_name}"
                elif lang == 'pt':
                    external_link = f"https://pt.dbpedia.org/page/{resource_name}"
                else:
                    external_link = f"http://dbpedia.org/page/{resource_name}"
                
                label = result["label"]["value"]
                abstract = result.get("abstract", {}).get("value", "")
                
                # Si no hay abstract, crear uno descriptivo
                if not abstract:
                    abstracts_by_lang = {
                        'en': f"Cybersecurity resource: {label}",
                        'es': f"Recurso de ciberseguridad: {label}",
                        'fr': f"Ressource de cybersécurité: {label}",
                        'de': f"Cybersicherheitsressource: {label}",
                        'it': f"Risorsa di cybersicurezza: {label}",
                        'pt': f"Recurso de cibersegurança: {label}"
                    }
                    abstract = abstracts_by_lang.get(lang, abstracts_by_lang['en'])
                elif len(abstract) > 200:
                    abstract = abstract[:197] + "..."
                
                formatted_result = {
                    'name': resource_name,
                    'label': label,
                    'type': 'DBPedia',
                    'comment': abstract,
                    'source': 'online',
                    'uri': resource_uri,
                    'relevance': 55,  # Alta relevancia para resultados de DBpedia
                    'external_link': external_link
                }
                formatted_results.append(formatted_result)
                
            except Exception as e:
                print(f"⚠️ Error procesando resultado DBpedia: {e}")
                continue
        
        print(f"✅ DBpedia ({lang}): {len(formatted_results)} resultados para '{query}'")
        return formatted_results
        
    except Exception as e:
        print(f"❌ Error en DBpedia ({lang}) para '{query}': {str(e)[:100]}")
        
        # Si falla un idioma no inglés, intentar en inglés
        if lang != 'en':
            print(f"🔄 Intentando fallback a inglés para '{query}'")
            try:
                # Llamada recursiva para buscar en inglés
                return search_dbpedia_online(query, 'en', limit)
            except Exception as e2:
                print(f"❌ Fallback a inglés falló: {e2}")
        
        return []

def search_hybrid(query, lang='es', filter_type='all', online_search=True):
    """Búsqueda híbrida: local + online"""
    all_results = []
    
    # BÚSQUEDA OFFLINE (Local)
    offline_results = []
    
    if filter_type == 'all' or filter_type == 'class':
        offline_results.extend(search_classes(query, lang))
    
    if filter_type == 'all' or filter_type == 'property':
        offline_results.extend(search_properties(query, lang))
    
    if filter_type == 'all' or filter_type == 'individual':
        offline_results.extend(search_individuals(query, lang))
    
    all_results.extend(offline_results)
    
    # BÚSQUEDA ONLINE (DBpedia) - Solo si está habilitada
    if online_search:
        online_results = search_dbpedia_online(query, lang, limit=15)
        all_results.extend(online_results)
    
    # Ordenar por relevancia
    all_results.sort(key=lambda x: x.get('relevance', 0), reverse=True)
    
    return all_results

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/search', methods=['GET'])
def search():
    query = request.args.get('q', '')
    lang = request.args.get('lang', 'es')
    filter_type = request.args.get('type', 'all')
    online = request.args.get('online', 'true').lower() == 'true'
    
    try:
        page = int(request.args.get('page', '1'))
    except ValueError:
        page = 1
    try:
        page_size = int(request.args.get('page_size', '50'))
    except ValueError:
        page_size = 50
    
    if not query:
        return jsonify({'error': 'Se requiere un término de búsqueda'}), 400
    
    if not ontology:
        return jsonify({'error': 'Ontología no cargada'}), 500
    
    # Búsqueda híbrida
    all_results = search_hybrid(query, lang, filter_type, online)
    
    # Estadísticas
    offline_count = sum(1 for r in all_results if r.get('source') == 'offline')
    online_count = sum(1 for r in all_results if r.get('source') == 'online')
    
    # Paginación
    total = len(all_results)
    start = (page - 1) * page_size
    end = start + page_size
    results_page = all_results[start:end]
    
    return jsonify({
        'query': query,
        'total': total,
        'page': page,
        'page_size': page_size,
        'online_enabled': online,
        'language': lang,
        'statistics': {
            'offline': offline_count,
            'online': online_count,
            'total': total
        },
        'results': results_page
    })

@app.route('/api/details/<entity_name>', methods=['GET'])
def get_details(entity_name):
    lang = request.args.get('lang', 'es')
    source = request.args.get('source', 'offline')
    
    # Textos traducidos para la interfaz
    translations = {
        'es': {
            'dbpedia_resource': 'Recurso DBpedia',
            'dbpedia_description': 'Información obtenida de DBpedia en línea',
            'view_on_dbpedia': 'Ver en DBpedia',
            'dbpedia_english': 'DBpedia (Inglés)',
            'dbpedia_english_desc': 'Información obtenida de DBpedia en inglés',
            'cybersecurity_resource': 'Recurso de ciberseguridad relacionado con',
            'class': 'Clase',
            'property': 'Propiedad',
            'individual': 'Individuo',
            'no_description': 'Sin descripción disponible'
        },
        'en': {
            'dbpedia_resource': 'DBpedia Resource',
            'dbpedia_description': 'Information obtained from DBpedia online',
            'view_on_dbpedia': 'View on DBpedia',
            'cybersecurity_resource': 'Cybersecurity resource related to',
            'class': 'Class',
            'property': 'Property',
            'individual': 'Individual',
            'no_description': 'No description available'
        },
        'fr': {
            'dbpedia_resource': 'Ressource DBpedia',
            'dbpedia_description': 'Informations obtenues depuis DBpedia en ligne',
            'view_on_dbpedia': 'Voir sur DBpedia',
            'dbpedia_english': 'DBpedia (Anglais)',
            'dbpedia_english_desc': 'Informations obtenues de DBpedia en anglais',
            'cybersecurity_resource': 'Ressource de cybersécurité liée à',
            'class': 'Classe',
            'property': 'Propriété',
            'individual': 'Individu',
            'no_description': 'Aucune description disponible'
        },
        'de': {
            'dbpedia_resource': 'DBpedia Ressource',
            'dbpedia_description': 'Informationen von DBpedia online erhalten',
            'view_on_dbpedia': 'Auf DBpedia anzeigen',
            'cybersecurity_resource': 'Cybersicherheitsressource im Zusammenhang mit',
            'class': 'Klasse',
            'property': 'Eigenschaft',
            'individual': 'Individuum',
            'no_description': 'Keine Beschreibung verfügbar'
        },
        'it': {
            'dbpedia_resource': 'Risorsa DBpedia',
            'dbpedia_description': 'Informazioni ottenute da DBpedia online',
            'view_on_dbpedia': 'Visualizza su DBpedia',
            'cybersecurity_resource': 'Risorsa di cybersicurezza relativa a',
            'class': 'Classe',
            'property': 'Proprietà',
            'individual': 'Individuo',
            'no_description': 'Nessuna descrizione disponibile'
        },
        'pt': {
            'dbpedia_resource': 'Recurso DBpedia',
            'dbpedia_description': 'Informações obtidas do DBpedia online',
            'view_on_dbpedia': 'Ver no DBpedia',
            'cybersecurity_resource': 'Recurso de cibersegurança relacionado a',
            'class': 'Classe',
            'property': 'Propriedade',
            'individual': 'Indivíduo',
            'no_description': 'Nenhuma descrição disponível'
        }
    }
    
    trans = translations.get(lang, translations['es'])
    
    if source == 'online':
        # Determinar el enlace externo según el idioma
        if lang == 'es':
            external_link = f"https://es.dbpedia.org/page/{entity_name}"
        elif lang == 'fr':
            external_link = f"https://fr.dbpedia.org/page/{entity_name}"
        elif lang == 'de':
            external_link = f"https://de.dbpedia.org/page/{entity_name}"
        elif lang == 'it':
            external_link = f"https://it.dbpedia.org/page/{entity_name}"
        elif lang == 'pt':
            external_link = f"https://pt.dbpedia.org/page/{entity_name}"
        else:
            external_link = f"http://dbpedia.org/page/{entity_name}"
        
        return jsonify({
            'name': entity_name,
            'label': entity_name.replace('_', ' ').title(),
            'type': trans['dbpedia_resource'],
            'comment': trans['dbpedia_description'],
            'source': 'online',
            'uri': f'http://dbpedia.org/resource/{entity_name}',
            'external_link': external_link,
            'language': lang,
            'translations': {
                'view_external': trans['view_on_dbpedia'],
                'type': trans['dbpedia_resource']
            }
        })
    
    # Lógica para detalles offline
    if not ontology:
        return jsonify({'error': 'Ontología no cargada'}), 500
    
    entity = None
    
    # Buscar en clases
    for cls in ontology.classes():
        if cls.name == entity_name:
            entity = cls
            break
    
    # Buscar en propiedades
    if not entity:
        for prop in list(ontology.object_properties()) + list(ontology.data_properties()):
            if prop.name == entity_name:
                entity = prop
                break
    
    # Buscar en individuos
    if not entity:
        for ind in ontology.individuals():
            if ind.name == entity_name:
                entity = ind
                break
    
    if not entity:
        return jsonify({'error': 'Entidad no encontrada'}), 404
    
    # Determinar el tipo de entidad traducido
    entity_type = None
    if isinstance(entity, type):
        entity_type = trans['class']
    elif hasattr(entity, 'domain'):
        entity_type = trans['property']
    else:
        entity_type = trans['individual']
    
    # Construir respuesta detallada
    details = {
        'name': entity.name,
        'label': get_label(entity, lang),
        'comment': get_comment(entity, lang) or trans['no_description'],
        'iri': entity.iri,
        'type': entity_type,
        'source': 'offline',
        'language': lang,
        'external_link': None,
        'translations': {
            'type': entity_type
        }
    }
    
    # Información específica según el tipo
    if isinstance(entity, type):
        details['parents'] = [{'name': p.name, 'label': get_label(p, lang)} 
                             for p in entity.is_a if isinstance(p, type)]
        details['subclasses'] = [{'name': s.name, 'label': get_label(s, lang)} 
                                for s in entity.subclasses()]
        details['instances'] = [{'name': i.name, 'label': get_label(i, lang)} 
                               for i in entity.instances()]
        
    elif hasattr(entity, 'domain'):
        details['domain'] = [{'name': d.name, 'label': get_label(d, lang)} 
                            for d in entity.domain] if entity.domain else []
        details['range'] = [{'name': r.name, 'label': get_label(r, lang)} 
                           for r in entity.range] if entity.range else []
    
    else:
        details['classes'] = [{'name': c.name, 'label': get_label(c, lang)} 
                             for c in entity.is_a if isinstance(c, type)]
    
    return jsonify(details)

@app.route('/api/stats', methods=['GET'])
def get_stats():
    """Estadísticas extendidas con información online/offline"""
    if not ontology:
        return jsonify({'error': 'Ontología no cargada'}), 500
    
    # Estadísticas locales
    local_stats = {
        'classes': len(list(ontology.classes())),
        'object_properties': len(list(ontology.object_properties())),
        'data_properties': len(list(ontology.data_properties())),
        'individuals': len(list(ontology.individuals())),
        'source': 'offline'
    }
    
    # Verificar disponibilidad de DBpedia para diferentes idiomas
    online_stats = {}
    for lang, endpoint in DBPEDIA_ENDPOINTS.items():
        try:
            sparql = SPARQLWrapper(endpoint)
            sparql.setQuery("SELECT * WHERE {?s ?p ?o} LIMIT 1")
            sparql.setReturnFormat(JSON)
            sparql.query().convert()
            online_stats[lang] = {
                'endpoint': endpoint,
                'available': True,
                'source': f'DBpedia {lang.upper()}'
            }
        except:
            online_stats[lang] = {
                'endpoint': endpoint,
                'available': False,
                'source': f'DBpedia {lang.upper()}'
            }
    
    return jsonify({
        'local': local_stats,
        'online': online_stats
    })

@app.route('/api/health', methods=['GET'])
def health_check():
    """Endpoint para verificar el estado del servicio"""
    status = {
        'status': 'healthy',
        'ontology_loaded': ontology is not None,
        'dbpedia_endpoints': DBPEDIA_ENDPOINTS
    }
    
    if ontology:
        status['ontology_stats'] = {
            'classes': len(list(ontology.classes())),
            'properties': len(list(ontology.object_properties())) + len(list(ontology.data_properties())),
            'individuals': len(list(ontology.individuals()))
        }
    
    # Verificar DBpedia endpoints
    dbpedia_status = {}
    for lang, endpoint in DBPEDIA_ENDPOINTS.items():
        try:
            sparql = SPARQLWrapper(endpoint)
            sparql.setQuery("SELECT * WHERE {?s ?p ?o} LIMIT 1")
            sparql.setReturnFormat(JSON)
            sparql.query().convert()
            dbpedia_status[lang] = 'available'
        except Exception as e:
            dbpedia_status[lang] = f'unavailable: {str(e)[:100]}'
    
    status['dbpedia_status'] = dbpedia_status
    
    return jsonify(status)

# Manejo de errores
@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Endpoint no encontrado'}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({'error': 'Error interno del servidor'}), 500

if __name__ == '__main__':
    print("🚀 Iniciando Motor de Búsqueda Ontológico Multilingüe...")
    print("📖 Cargando ontología...")
    load_ontology()
    print("✅ Servicio listo")
    print("🌐 Idiomas disponibles: ES, EN, FR, DE, IT, PT")
    print("🔗 URL: http://127.0.0.1:5000")
    app.run(debug=True, host='0.0.0.0', port=5000)
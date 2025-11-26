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
DBPEDIA_ENDPOINT = "https://dbpedia.org/sparql"

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
            for label in labels:
                if hasattr(label, 'lang') and label.lang == lang:
                    return str(label)
            return str(labels[0]) if labels else entity.name
    return entity.name

def get_comment(entity, lang='es'):
    """Obtiene el comentario en el idioma especificado"""
    if hasattr(entity, 'comment'):
        comments = entity.comment
        if comments:
            for comment in comments:
                if hasattr(comment, 'lang') and comment.lang == lang:
                    return str(comment)
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
            parents = [get_label(p, lang) for p in cls.is_a if isinstance(p, type)]
            subclasses = [get_label(sub, lang) for sub in cls.subclasses()]
            
            results.append({
                'name': cls.name,
                'label': label_display,
                'type': 'Clase',
                'comment': get_comment(cls, lang) or "Clase de ciberseguridad",
                'parents': parents[:3],
                'subclasses': subclasses[:5],
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
            domain = [get_label(d, lang) for d in prop.domain] if prop.domain else []
            range_val = [get_label(r, lang) for r in prop.range] if prop.range else []
            
            results.append({
                'name': prop.name,
                'label': label_display,
                'type': 'Propiedad',
                'comment': get_comment(prop, lang) or "Propiedad de la ontología",
                'domain': domain,
                'range': range_val,
                'relevance': calculate_relevance(query_lower, label, name, comment, 'property'),
                'source': 'offline'
            })
    
    for prop in ontology.data_properties():
        label_display = get_label(prop, lang)
        label = normalize_text(label_display)
        comment = normalize_text(get_comment(prop, lang))
        name = normalize_text(prop.name)
        
        if query_lower in label or query_lower in name or query_lower in comment:
            domain = [get_label(d, lang) for d in prop.domain] if prop.domain else []
            
            results.append({
                'name': prop.name,
                'label': label_display,
                'type': 'Propiedad',
                'comment': get_comment(prop, lang) or "Propiedad de datos",
                'domain': domain,
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
            classes = [get_label(c, lang) for c in ind.is_a if isinstance(c, type)]
            
            results.append({
                'name': ind.name,
                'label': label_display,
                'type': 'Individuo',
                'comment': get_comment(ind, lang) or "Instancia de ciberseguridad",
                'classes': classes,
                'relevance': calculate_relevance(query_lower, label, name, comment, 'individual'),
                'source': 'offline'
            })
    
    return results

def calculate_relevance(query, label, name, comment, entity_type):
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

def search_dbpedia_online(query, lang='en', limit=10):
    """Busca en DBpedia limitado a dominios de ciberseguridad"""
    try:
        sparql = SPARQLWrapper(DBPEDIA_ENDPOINT)
        sparql.addCustomHttpHeader("User-Agent", "CybersecuritySearchBot/1.0")
        
        search_query = f"""
        PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
        PREFIX dbo: <http://dbpedia.org/ontology/>
        PREFIX dct: <http://purl.org/dc/terms/>
        PREFIX category: <http://dbpedia.org/resource/Category:>

        SELECT DISTINCT ?resource ?label ?abstract WHERE {{
          {{
            ?resource rdfs:label ?label .
            FILTER(CONTAINS(LCASE(?label), "{query.lower()}") && LANG(?label) = 'en')
            
            # Filtrar por categorías específicas de ciberseguridad
            ?resource dct:subject ?category .
            FILTER(
              CONTAINS(LCASE(STR(?category)), "cyber") ||
              CONTAINS(LCASE(STR(?category)), "security") ||
              CONTAINS(LCASE(STR(?category)), "malware") ||
              CONTAINS(LCASE(STR(?category)), "ransomware") ||
              CONTAINS(LCASE(STR(?category)), "hacker") ||
              CONTAINS(LCASE(STR(?category)), "vulnerability") ||
              CONTAINS(LCASE(STR(?category)), "encryption") ||
              CONTAINS(LCASE(STR(?category)), "computer_virus") ||
              CONTAINS(LCASE(STR(?category)), "information_security")
            )
            
            OPTIONAL {{ ?resource dbo:abstract ?abstract . FILTER(LANG(?abstract) = 'en') }}
          }}
        }}
        LIMIT {limit}
        """
        
        sparql.setQuery(search_query)
        sparql.setReturnFormat(JSON)
        results = sparql.query().convert()
        
        formatted_results = []
        for result in results["results"]["bindings"]:
            resource_uri = result["resource"]["value"]
            resource_name = resource_uri.split("/")[-1]
            
            comment = result.get("abstract", {}).get("value", "")
            if not comment:
                comment = f"Recurso de ciberseguridad relacionado con '{query}'"
            else:
                if len(comment) > 200:
                    comment = comment[:197] + "..."
            
            formatted_result = {
                'name': resource_name,
                'label': result["label"]["value"],
                'type': 'DBPedia',
                'comment': comment,
                'source': 'online',
                'uri': resource_uri,
                'relevance': 45,
                'external_link': f"http://dbpedia.org/page/{resource_name}"
            }
            formatted_results.append(formatted_result)
        
        return formatted_results
        
    except Exception as e:
        print(f"❌ Error en búsqueda online DBpedia: {e}")
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
    
    # BÚSQUEDA ONLINE (DBpedia)
    if online_search:
        online_results = search_dbpedia_online(query, 'en', limit=15)
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
    
    if source == 'online':
        # Para recursos online, devolver información básica
        return jsonify({
            'name': entity_name,
            'label': entity_name.replace('_', ' '),
            'type': 'Recurso DBpedia',
            'comment': 'Información obtenida de DBpedia en línea',
            'source': 'online',
            'uri': f'http://dbpedia.org/resource/{entity_name}',
            'external_link': f'http://dbpedia.org/page/{entity_name}'
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
    
    # Construir respuesta detallada
    details = {
        'name': entity.name,
        'label': get_label(entity, lang),
        'comment': get_comment(entity, lang) or "Sin descripción disponible",
        'iri': entity.iri,
        'source': 'offline',
        'external_link': None
    }
    
    # Información específica según el tipo
    if isinstance(entity, type):
        details['type'] = 'Clase'
        details['parents'] = [{'name': p.name, 'label': get_label(p, lang)} 
                             for p in entity.is_a if isinstance(p, type)]
        details['subclasses'] = [{'name': s.name, 'label': get_label(s, lang)} 
                                for s in entity.subclasses()]
        details['instances'] = [{'name': i.name, 'label': get_label(i, lang)} 
                               for i in entity.instances()]
        
    elif hasattr(entity, 'domain'):
        details['type'] = 'Propiedad'
        details['domain'] = [{'name': d.name, 'label': get_label(d, lang)} 
                            for d in entity.domain] if entity.domain else []
        details['range'] = [{'name': r.name, 'label': get_label(r, lang)} 
                           for r in entity.range] if entity.range else []
    
    else:
        details['type'] = 'Individuo'
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
    
    return jsonify({
        'local': local_stats,
        'online': {
            'endpoint': DBPEDIA_ENDPOINT,
            'available': True,
            'source': 'DBpedia'
        }
    })

if __name__ == '__main__':
    load_ontology()
    app.run(debug=True, host='0.0.0.0', port=5000)
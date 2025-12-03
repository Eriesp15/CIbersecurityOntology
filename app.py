from flask import Flask, render_template, request, jsonify
from flask_cors import CORS
from owlready2 import get_ontology, locstr
import unicodedata
import os
from SPARQLWrapper import SPARQLWrapper, JSON
import re
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError
import time

app = Flask(__name__, template_folder='templates')
CORS(app)

# Cargar la ontología
ontology = None
ONTOLOGY_PATH = "CibersecurityOntology.rdf"

# Endpoints de DBpedia por idioma
DBPEDIA_ENDPOINTS = {
    'es': 'https://es.dbpedia.org/sparql',
    'en': 'https://dbpedia.org/sparql',
    'fr': 'https://fr.dbpedia.org/sparql'
}

# Configuración de timeouts más agresiva
SPARQL_TIMEOUT = 8  # Reducido de 20 a 8 segundos
MAX_QUERY_TIME = 10  # Tiempo máximo total por consulta

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
            # Fallback: primera etiqueta disponible
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
    
    default_comments = {
        'es': "Sin descripción disponible",
        'en': "No description available",
        'fr': "Aucune description disponible"
    }
    return default_comments.get(lang, default_comments['es'])

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

def execute_sparql_with_timeout(sparql, timeout=SPARQL_TIMEOUT):
    """Ejecuta una consulta SPARQL con timeout usando ThreadPoolExecutor"""
    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(sparql.query)
        try:
            return future.result(timeout=timeout)
        except FuturesTimeoutError:
            print(f"⏰ Timeout en consulta SPARQL ({timeout}s)")
            return None
        except Exception as e:
            print(f"❌ Error en consulta SPARQL: {e}")
            return None

def get_simplified_query(query, lang):
    """Genera consulta SPARQL simplificada y más permisiva"""
    safe_query = query.replace('"', r'\"').replace("'", r"\'")
    
    # Palabras clave de ciberseguridad por idioma
    cybersec_terms = {
        'en': 'cyber|security|malware|ransomware|hacker|virus|attack|encryption|phishing|firewall',
        'es': 'ciber|seguridad|malware|ransomware|hacker|virus|ataque|encriptación|phishing|cortafuegos',
        'fr': 'cyber|sécurité|malware|rançongiciel|pirate|virus|attaque|chiffrement|hameçonnage|pare-feu'
    }
    
    terms = cybersec_terms.get(lang, cybersec_terms['en'])
    
    return f"""
    PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
    PREFIX dbo: <http://dbpedia.org/ontology/>
    
    SELECT DISTINCT ?resource ?label ?abstract WHERE {{
      {{
        ?resource rdfs:label ?label .
        FILTER(LANG(?label) = '{lang}')
        FILTER(REGEX(LCASE(?label), "{safe_query.lower()}", "i"))
      }}
      UNION
      {{
        ?resource rdfs:label ?label .
        FILTER(LANG(?label) = '{lang}')
        FILTER(REGEX(LCASE(?label), "({terms})", "i"))
        FILTER(REGEX(LCASE(?label), "{safe_query.lower()[0:3]}", "i"))
      }}
      
      OPTIONAL {{
        ?resource dbo:abstract ?abstract .
        FILTER(LANG(?abstract) = '{lang}')
      }}
    }}
    LIMIT 20
    """

def search_dbpedia_online(query, lang='en', limit=10):
    """Búsqueda optimizada en DBpedia con timeout agresivo"""
    start_time = time.time()
    
    try:
        print(f"🔍 Búsqueda online: '{query}' en {lang}")
        
        # Seleccionar endpoint
        endpoint = DBPEDIA_ENDPOINTS.get(lang, DBPEDIA_ENDPOINTS['en'])
        
        sparql = SPARQLWrapper(endpoint)
        sparql.addCustomHttpHeader("User-Agent", "CybersecuritySearchBot/3.0")
        sparql.setTimeout(SPARQL_TIMEOUT)
        
        # Usar consulta simplificada
        search_query = get_simplified_query(query, lang)
        
        sparql.setQuery(search_query)
        sparql.setReturnFormat(JSON)
        
        # Ejecutar con timeout
        response = execute_sparql_with_timeout(sparql, timeout=SPARQL_TIMEOUT)
        
        if response is None:
            print(f"⚠️ Timeout o error en {lang}, usando fallback")
            return get_fallback_results(query, lang)
        
        try:
            raw_results = response.convert()["results"]["bindings"]
            print(f"📊 Resultados obtenidos: {len(raw_results)}")
        except Exception as e:
            print(f"❌ Error parseando respuesta: {e}")
            return get_fallback_results(query, lang)
        
        # Procesar resultados
        formatted_results = []
        seen_resources = set()
        
        for result in raw_results[:limit]:
            try:
                resource_uri = result["resource"]["value"]
                
                if resource_uri in seen_resources:
                    continue
                seen_resources.add(resource_uri)
                
                resource_name = resource_uri.split("/")[-1]
                label = result["label"]["value"]
                
                # Obtener comentario
                comment = result.get("abstract", {}).get("value", "")
                if not comment:
                    comment = get_default_comment(query, lang)
                else:
                    if len(comment) > 200:
                        comment = comment[:197] + "..."
                
                # Construir enlace externo
                external_link = get_external_link(resource_name, lang)
                
                # Calcular relevancia
                relevance = calculate_online_relevance(query, label, comment)
                
                formatted_result = {
                    'name': resource_name,
                    'label': label,
                    'type': 'DBPedia',
                    'comment': comment,
                    'source': 'online',
                    'uri': resource_uri,
                    'relevance': relevance,
                    'external_link': external_link,
                    'translations': {
                        'type': {
                            'es': 'Recurso DBpedia',
                            'en': 'DBPedia Resource',
                            'fr': 'Ressource DBpedia'
                        },
                        'comment': comment,
                        'view_external': {
                            'es': 'Ver en DBpedia',
                            'en': 'View on DBpedia',
                            'fr': 'Voir sur DBpedia'
                        }
                    }
                }
                formatted_results.append(formatted_result)
                    
            except Exception as e:
                print(f"⚠️ Error procesando resultado: {e}")
                continue
        
        elapsed = time.time() - start_time
        print(f"✅ Búsqueda online ({lang}): {len(formatted_results)} resultados en {elapsed:.2f}s")
        
        # Si hay pocos resultados, añadir fallback
        if len(formatted_results) < 3:
            fallback = get_fallback_results(query, lang)
            formatted_results.extend(fallback[:5])
        
        return formatted_results
        
    except Exception as e:
        elapsed = time.time() - start_time
        print(f"❌ Error crítico en búsqueda online ({lang}) después de {elapsed:.2f}s: {e}")
        return get_fallback_results(query, lang)

def get_default_comment(query, lang):
    """Devuelve comentario por defecto según idioma"""
    comments = {
        'es': f"Recurso de ciberseguridad relacionado con '{query}'",
        'en': f"Cybersecurity resource related to '{query}'",
        'fr': f"Ressource de cybersécurité liée à '{query}'"
    }
    return comments.get(lang, comments['en'])

def get_external_link(resource_name, lang):
    """Construye el enlace externo según el idioma"""
    if lang == 'es':
        return f"https://es.dbpedia.org/page/{resource_name}"
    elif lang == 'fr':
        return f"https://fr.dbpedia.org/page/{resource_name}"
    else:
        return f"http://dbpedia.org/page/{resource_name}"

def calculate_online_relevance(query, label, comment):
    """Calcula relevancia para resultados online"""
    score = 0
    query_lower = query.lower()
    label_lower = label.lower()
    comment_lower = comment.lower() if comment else ""
    
    if query_lower == label_lower:
        score += 100
    elif query_lower in label_lower:
        score += 60
    
    if comment and query_lower in comment_lower:
        score += 30
    
    security_terms = ['security', 'cyber', 'malware', 'ransomware', 'hacker', 
                     'seguridad', 'ciber', 'sécurité']
    for term in security_terms:
        if term in label_lower or term in comment_lower:
            score += 10
    
    score -= len(label_lower) * 0.05
    
    return max(10, min(score, 100))

def get_fallback_results(query, lang):
    """Devuelve resultados de fallback mejorados y más numerosos"""
    print(f"🔄 Usando resultados de fallback para {lang}: '{query}'")
    
    # Recursos conocidos expandidos
    known_resources = {
        'es': [
            ('Malware', 'Software malicioso diseñado para dañar sistemas'),
            ('Ciberseguridad', 'Protección de sistemas informáticos y datos'),
            ('Ransomware', 'Malware que cifra archivos y exige rescate'),
            ('Phishing', 'Ataque de ingeniería social para robar información'),
            ('Cortafuegos', 'Sistema de seguridad de red'),
            ('Encriptación', 'Proceso de codificación de información'),
            ('Hacker', 'Persona experta en sistemas informáticos'),
            ('Virus', 'Programa malicioso que se replica'),
            ('Spyware', 'Software espía que recopila información'),
            ('DDoS', 'Ataque de denegación de servicio distribuido'),
            ('Vulnerabilidad', 'Debilidad en sistemas de seguridad'),
            ('Autenticación', 'Verificación de identidad de usuarios')
        ],
        'en': [
            ('Malware', 'Malicious software designed to harm systems'),
            ('Cybersecurity', 'Protection of computer systems and data'),
            ('Ransomware', 'Malware that encrypts files for ransom'),
            ('Phishing', 'Social engineering attack to steal information'),
            ('Firewall', 'Network security system'),
            ('Encryption', 'Process of encoding information'),
            ('Hacker', 'Person skilled in computer systems'),
            ('Virus', 'Malicious self-replicating program'),
            ('Spyware', 'Software that secretly gathers information'),
            ('DDoS', 'Distributed denial-of-service attack'),
            ('Vulnerability', 'Weakness in security systems'),
            ('Authentication', 'Verification of user identity')
        ],
        'fr': [
            ('Logiciel_malveillant', 'Logiciel malveillant conçu pour endommager les systèmes'),
            ('Cybersécurité', 'Protection des systèmes informatiques et des données'),
            ('Rançongiciel', 'Logiciel malveillant qui chiffre les fichiers'),
            ('Hameçonnage', "Attaque d'ingénierie sociale pour voler des informations"),
            ('Pare-feu', 'Système de sécurité réseau'),
            ('Chiffrement', "Processus d'encodage de l'information"),
            ('Pirate_informatique', 'Personne experte en systèmes informatiques'),
            ('Virus', 'Programme malveillant auto-répliquant'),
            ('Logiciel_espion', 'Logiciel qui collecte secrètement des informations'),
            ('DDoS', 'Attaque par déni de service distribué'),
            ('Vulnérabilité', 'Faiblesse dans les systèmes de sécurité'),
            ('Authentification', "Vérification de l'identité des utilisateurs")
        ]
    }
    
    resources = known_resources.get(lang, known_resources['en'])
    query_lower = query.lower()
    
    results = []
    for name, description in resources:
        # Buscar coincidencias más flexibles
        if (query_lower in name.lower() or 
            query_lower in description.lower() or
            any(q in name.lower() for q in query_lower.split())):
            
            results.append({
                'name': name,
                'label': name.replace('_', ' '),
                'type': 'DBPedia',
                'comment': description,
                'source': 'online',
                'uri': f'http://dbpedia.org/resource/{name}',
                'relevance': 50,
                'external_link': get_external_link(name, lang),
                'translations': {
                    'type': {
                        'es': 'Recurso DBpedia',
                        'en': 'DBPedia Resource',
                        'fr': 'Ressource DBpedia'
                    },
                    'comment': description,
                    'view_external': {
                        'es': 'Ver en DBpedia',
                        'en': 'View on DBpedia',
                        'fr': 'Voir sur DBpedia'
                    }
                }
            })
    
    return results

def search_hybrid(query, lang='es', filter_type='all', online_search=True):
    """Búsqueda híbrida: local + online con timeout total"""
    start_time = time.time()
    all_results = []
    
    # BÚSQUEDA OFFLINE (Local) - rápida
    offline_results = []
    
    if filter_type == 'all' or filter_type == 'class':
        offline_results.extend(search_classes(query, lang))
    
    if filter_type == 'all' or filter_type == 'property':
        offline_results.extend(search_properties(query, lang))
    
    if filter_type == 'all' or filter_type == 'individual':
        offline_results.extend(search_individuals(query, lang))
    
    all_results.extend(offline_results)
    
    # BÚSQUEDA ONLINE (DBpedia) - con timeout
    if online_search:
        elapsed = time.time() - start_time
        remaining_time = MAX_QUERY_TIME - elapsed
        
        if remaining_time > 2:
            online_results = search_dbpedia_online(query, lang, limit=15)
            all_results.extend(online_results)
        else:
            print(f"⏰ Tiempo agotado, saltando búsqueda online")
            all_results.extend(get_fallback_results(query, lang)[:5])
    
    # Ordenar por relevancia
    all_results.sort(key=lambda x: x.get('relevance', 0), reverse=True)
    
    total_time = time.time() - start_time
    print(f"⏱️ Búsqueda total completada en {total_time:.2f}s")
    
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
        type_translations = {
            'es': 'Recurso DBpedia',
            'en': 'DBpedia Resource',
            'fr': 'Ressource DBpedia'
        }
        comment_translations = {
            'es': 'Información obtenida de DBpedia en línea',
            'en': 'Information obtained from DBpedia online',
            'fr': 'Informations obtenues depuis DBpedia en ligne'
        }
        
        return jsonify({
            'name': entity_name,
            'label': entity_name.replace('_', ' '),
            'type': type_translations.get(lang, 'DBpedia Resource'),
            'comment': comment_translations.get(lang, 'Information obtained from DBpedia online'),
            'source': 'online',
            'uri': f'http://dbpedia.org/resource/{entity_name}',
            'external_link': f'http://dbpedia.org/page/{entity_name}',
            'translations': {
                'type': type_translations,
                'comment': comment_translations,
                'view_external': {
                    'es': 'Ver en DBpedia',
                    'en': 'View on DBpedia',
                    'fr': 'Voir sur DBpedia'
                }
            }
        })
    
    if not ontology:
        return jsonify({'error': 'Ontología no cargada'}), 500
    
    entity = None
    
    for cls in ontology.classes():
        if cls.name == entity_name:
            entity = cls
            break
    
    if not entity:
        for prop in list(ontology.object_properties()) + list(ontology.data_properties()):
            if prop.name == entity_name:
                entity = prop
                break
    
    if not entity:
        for ind in ontology.individuals():
            if ind.name == entity_name:
                entity = ind
                break
    
    if not entity:
        return jsonify({'error': 'Entidad no encontrada'}), 404
    
    details = {
        'name': entity.name,
        'label': get_label(entity, lang),
        'comment': get_comment(entity, lang),
        'iri': entity.iri,
        'source': 'offline',
        'external_link': None,
        'translations': {
            'type': {
                'es': '',
                'en': '',
                'fr': ''
            },
            'view_external': {
                'es': 'Ver detalles',
                'en': 'View details',
                'fr': 'Voir détails'
            }
        }
    }
    
    if isinstance(entity, type):
        details['type'] = 'Clase'
        details['translations']['type'] = {
            'es': 'Clase',
            'en': 'Class',
            'fr': 'Classe'
        }
        details['parents'] = [{'name': p.name, 'label': get_label(p, lang)} 
                             for p in entity.is_a if isinstance(p, type)]
        details['subclasses'] = [{'name': s.name, 'label': get_label(s, lang)} 
                                for s in entity.subclasses()]
        details['instances'] = [{'name': i.name, 'label': get_label(i, lang)} 
                               for i in entity.instances()]
        
    elif hasattr(entity, 'domain'):
        details['type'] = 'Propiedad'
        details['translations']['type'] = {
            'es': 'Propiedad',
            'en': 'Property',
            'fr': 'Propriété'
        }
        details['domain'] = [{'name': d.name, 'label': get_label(d, lang)} 
                            for d in entity.domain] if entity.domain else []
        details['range'] = [{'name': r.name, 'label': get_label(r, lang)} 
                           for r in entity.range] if entity.range else []
    
    else:
        details['type'] = 'Individuo'
        details['translations']['type'] = {
            'es': 'Individuo',
            'en': 'Individual',
            'fr': 'Individu'
        }
        details['classes'] = [{'name': c.name, 'label': get_label(c, lang)} 
                             for c in entity.is_a if isinstance(c, type)]
    
    return jsonify(details)

@app.route('/api/stats', methods=['GET'])
def get_stats():
    """Estadísticas extendidas con información online/offline"""
    if not ontology:
        return jsonify({'error': 'Ontología no cargada'}), 500
    
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
            'endpoint': DBPEDIA_ENDPOINTS,
            'available': True,
            'source': 'DBpedia Multilingüe'
        }
    })

if __name__ == '__main__':
    load_ontology()
    app.run(debug=True, host='0.0.0.0', port=5000)